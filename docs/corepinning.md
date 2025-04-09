# Core Pinning for Calico/VPP

This patch adds support in VPP for pinning workers to the CPU
cores that are assigned by a static allocator.

When kubernetes is configured to run with a [static allocator](https://kubernetes.io/docs/tasks/administer-cluster/cpu-management-policies/#static-policy
) and that VPP starts with requests.CPU equal to limits.CPU
and both integer numbers.

having VPP configured with

```console
cpu {
   main-core 0
   corelist-workers 2-3
   relative
}
```

Will make it so that numbers 0,2,3 do not refer to absolutes CPU
IDs but to the 0th, 2nd and 3rd CPU of those allotted by the static
core allocator in kubernetes.
