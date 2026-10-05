const ORDERS = "/api/v1/orders?limit=20";
const DETAIL = "/api/v1/users/123?verbose=1";
fetch(ORDERS).then((r) => r.json());
fetch(DETAIL).then((r) => r.json());
//# sourceMappingURL=app.js.map
