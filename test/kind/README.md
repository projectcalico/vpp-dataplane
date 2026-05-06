# Testing with kind

## Calico Kubernetes versions matrix

The following table represent the compatibility matrix between:

- Calico version `3.X`
- k8s versions `1.X`
- kind versions `0.X`

| k8s  | 3.32 | 3.31 | 3.30 | 3.29 | 3.28 | 3.27 | 3.26 | Kind      |
| :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :-------: |
| 1.36 |  X   |  X   |  X   |      |      |      |      | 0.32?     |
| 1.35 |  X   |  X   |  X   |      |      |      |      | 0.31      |
| 1.34 |  X   |  X   |  X   |      |      |      |      | 0.30      |
| 1.33 |      |  X   |  X   |      |      |      |      | 0.29      |
| 1.32 |      |  X   |  X   |  X   |      |      |      | 0.26-0.28 |
| 1.31 |      |      |  X   |  X   |      |      |      | 0.24-0.25 |
| 1.30 |      |      |  X   |  X   |   X  |      |      | 0.23      |
| 1.29 |      |      |  X   |  X   |   X  |  X   |      | 0.21-0.22 |
| 1.28 |      |      |      |      |   X  |  X   |  X   | 0.20      |
| 1.27 |      |      |      |      |   X  |  X   |  X   | 0.19      |
| 1.26 |      |      |      |      |      |      |  X   | 0.18      |
| 1.25 |      |      |      |      |      |      |  X   | 0.16-0.17 |
| 1.24 |      |      |      |      |      |      |  X   | 0.15      |

[Source](https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements#kubernetes-requirements)
