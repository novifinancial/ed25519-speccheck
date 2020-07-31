# ed25519-speccheck


## Condition table

```
| parameters              | cofactored      | cofactorless                   | comment                            |
|-------------------------+-----------------+--------------------------------+------------------------------------|
| s = 0, R small, A small | always passes   | R = -k×A                       | see ed25519's verify_strict        |
| s > 0, R small, A small | always fails    | always fails                   | no large order component on the r. |
| s = 0, R mixed, A small | always fails    | always fails                   | no large order component on the l. |
| s > 0, R mixed, A small | 8×s×B = 8×R     | 8×s×B = 8×R ∧ L×R = -L×k×A     | [1]                                |
| s = 0, R small, A mixed | always fails    | always fails                   | no large order component on the l. |
| s > 0, R small, A mixed | 8×s×B = 8×k×A   | 8×s×B = 8×k×A ∧ L×R = -L×k×A   | symmetric of [1]                   |
| s = 0, R mixed, A mixed | 8×R = -8×k×A    | R = - k×A                      | hard to test (req. hash inversion) |
| s > 0, R mixed, A mixed | 8×s×B = 8×R+k×A | 8×s×B = 8×R+k×A ∧ L×R = -L×k×A |                                    |
```

Here "mixed" means with a strictly positive torsion component but not small,
i.e. "mixed" and "small" are mutually exclusive.

## Randomized batching
