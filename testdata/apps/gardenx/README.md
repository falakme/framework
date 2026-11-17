# GardenX

Two apps that talk through Falak Office events (FEDERATION §13).

| App | What it owns | Events |
|---|---|---|
| `orders` | `purchase` (sku, qty) | publishes `order_placed` when a purchase is created, to `inventory`. Starts the saga `fulfil_order` on it. |
| `inventory` | `reservation`, `stock_move` | consumes `order_placed` (creates a `reservation`), and the saga's `confirm_stock` and `cancel_stock` (create a `stock_move`). |

```
orders ──outbox──> Office Events ──delivery──> inventory (inbox)
                        │
                        └─ saga fulfil_order: confirm_stock, or cancel_stock if a step fails
```

* A new order and its event are written in one transaction (the outbox), so an order is never without its event.
* Office stores the event before it answers the sender, and delivers it to `inventory` until `inventory` has recorded it. Inventory applies each event once (the inbox), so a redelivery does nothing.
* `inventory` lets only the role `event_consumer` create reservations and stock moves. That is the policy that authorises events; nobody else can write those rows through the API.
* The `fulfil_order` saga sends `confirm_stock` for each order. If a step failed for good, Office would send `cancel_stock` for the steps already done.

## Run it

Events need both apps enrolled with Office (see the Office smoke test for the full steps).

```sh
falak-office serve --port 8788                          # then set up an administrator
falak office enroll testdata/apps/gardenx/orders    --office http://127.0.0.1:8788 --token <token> --name orders
falak office enroll testdata/apps/gardenx/inventory --office http://127.0.0.1:8788 --token <token> --name inventory
falak serve testdata/apps/gardenx/orders    --port 8801
falak serve testdata/apps/gardenx/inventory --port 8802
```

`scripts/smoke/events.sh` does all of this, places 120 orders, kills Office twice and the inventory app once with `SIGKILL` meanwhile, and checks that the orders and the reservations match one for one.

**Limits.** An event carries the fields the change had when it was made, not the whole row. A handler is a `create` command. See FEDERATION §13.7.
