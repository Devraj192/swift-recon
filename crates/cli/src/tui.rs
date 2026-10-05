//! Minimal full-screen scan browser: stored scans on top, selected scan
//! detail below. Arrow keys move, Enter pins the selection, q/Esc quits.
//! Same SQLite history as the CLI; read-only, changes nothing.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;
use std::io;
use std::time::Duration;
use swiftrecon_core::Fact;
use swiftrecon_store::{Store, StoredScan};

struct App {
    scans: Vec<StoredScan>,
    facts: Vec<Fact>,
    selected: usize,
    detail: Vec<String>,
}

impl App {
    fn load(store: &Store) -> Result<Self> {
        let scans = store.list_scans().unwrap_or_default();
        let mut app = Self {
            scans,
            facts: Vec::new(),
            selected: 0,
            detail: vec!["No scans yet. Run `swiftrecon scan`.".to_string()],
        };
        app.refresh_detail(store);
        Ok(app)
    }

    fn refresh_detail(&mut self, store: &Store) {
        let Some(scan) = self.scans.get(self.selected) else {
            return;
        };
        let facts = store.get_facts(&scan.id).unwrap_or_default();
        let mut lines = vec![
            format!("scan: {}", scan.id),
            format!("status: {} (started {})", scan.status, scan.started),
            format!("facts: {}", facts.len()),
            String::new(),
        ];
        for fact in facts.iter().take(200) {
            lines.push(format!(
                "[{}] {} ({})",
                fact.kind,
                truncate(&fact.value, 60),
                fact.sources.join(",")
            ));
        }
        if facts.len() > 200 {
            lines.push(format!("... and {} more", facts.len() - 200));
        }
        self.facts = facts;
        self.detail = lines;
    }
}

fn truncate(s: &str, max: usize) -> String {
    let clean: String = s.chars().filter(|c| !c.is_control()).collect();
    if clean.len() > max {
        format!("{}...", &clean[..max])
    } else {
        clean
    }
}

pub fn run(db: &std::path::Path) -> Result<()> {
    let store = Store::open(db)?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let outcome = run_loop(&mut terminal, &store);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    outcome
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, store: &Store) -> Result<()> {
    let mut app = App::load(store)?;
    let mut state = ListState::default();
    state.select(Some(app.selected));
    loop {
        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(10), Constraint::Min(0)])
                .split(frame.area());
            let items: Vec<ListItem> = app
                .scans
                .iter()
                .map(|scan| ListItem::new(format!("{} [{}]", scan.id, scan.status)))
                .collect();
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Scans"))
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );
            frame.render_stateful_widget(list, chunks[0], &mut state);
            let detail = Paragraph::new(app.detail.join("\n"))
                .block(Block::default().borders(Borders::ALL).title("Detail"));
            frame.render_widget(detail, chunks[1]);
        })?;
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Down | KeyCode::Char('j') => {
                if !app.scans.is_empty() {
                    app.selected = (app.selected + 1) % app.scans.len();
                    state.select(Some(app.selected));
                    app.refresh_detail(store);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !app.scans.is_empty() {
                    app.selected = if app.selected == 0 {
                        app.scans.len() - 1
                    } else {
                        app.selected - 1
                    };
                    state.select(Some(app.selected));
                    app.refresh_detail(store);
                }
            }
            KeyCode::Enter => app.refresh_detail(store),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_loads_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("tui.db");
        let store = Store::open(&db).unwrap();
        let app = App::load(&store).unwrap();
        assert!(app.scans.is_empty());
        assert!(app.detail.join("\n").contains("No scans yet"));
    }

    #[test]
    fn truncate_strips_control() {
        assert_eq!(truncate("ab\x00cdefgh", 5), "abcde...");
        assert_eq!(truncate("ok", 5), "ok");
    }
}
