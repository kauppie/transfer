# Steps to containerized application

Tutorial: https://www.youtube.com/watch?v=X48VuDVv0do&t=8222s

minikube runs as a container -> may need manual start up.

Docs for running with podman: https://minikube.sigs.k8s.io/docs/drivers/podman/

```
minikube start --driver=podman --container-runtime=containerd
```

## Building container image using Dockerfile

```
podman build .
```

```
podman build -t <name>:<tag> .
```

## Various commands

```
kubectl cluster-info
```

```
kubectl get po -A
```

Open dashboard to cluster in default web browser.

```
minikube dashboard
```

Get states of different components.

```
kubectl get all
kubectl get nodes
kubectl get pods
kubectl get services
kubectl get replicaset
kubectl get deployment

kubectl logs [POD]
kubectl exec -it [POD] -- /bin/bash
kubectl describe pod [POD NAME]
```

```
kubectl create deployment NAME --image=image
```

Create deployment from predefined file. If applied multiple times, K8s will change the state to match most up-to-date configuration.

```
kubectl apply -f [FILE]
kubectl delete -f [FILE]
```
