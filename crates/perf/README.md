# SP1 Testing Suite

## Prerequisites

- [GitHub CLI](https://cli.github.com/)

## Run the testing suite

Set the workloads you want to run in the `workflow.sh` file. The workloads are keys in the 
`sp1-testing-suite` s3 bucket.

```
CPU_WORKLOADS=("fibonacci-17k" "ssz-withdrawals")
CUDA_WORKLOADS=()
NETWORK_WORKLOADS=()
```

Run the workflow.
```
./workflow.sh
```

## View the results

Visit the [actions](https://github.com/succinctlabs/sp1/actions) tab on GitHub to view the results.