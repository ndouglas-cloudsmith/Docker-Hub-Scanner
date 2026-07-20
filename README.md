# DockerHub Scanner
Unified Docker Hub scanner to check for the below information:
- Known Exploitable Vulnerabilities
- Intentionally Malicious Software Dependencies

```
wget https://raw.githubusercontent.com/ndouglas-cloudsmith/Docker-Hub-Scanner/refs/heads/main/DockerScanner.py
python3 DockerScanner.py
```

| Github Repos | Docker Hub |
| --- | --- |
| github.com/wearenotpoliticallycorrect/docker-image | `d0whc3r/kali-ssh` |
| github.com/dvkunion/test_ci | `pmietlicki/yada-miner` |
| github.com/ckmaenn/shello-2105 | `metal3d/xmrig` |

You can run it directly with positional arguments or fall back to interactive prompt if omitted:

Scan for a specific docker container called ```metal3d/xmrig```
```
python3 DockerScanner.py metal3d/xmrig
```

Find only ```HIGH``` CVEs for the image:
```
python3 DockerScanner.py metal3d/xmrig --high
```

Find only ```CRITICAL``` CVEs for the image:
```
python3 DockerScanner.py metal3d/xmrig --critical
```

Find ```HIGH``` and ```CRITICAL``` CVEs for the same container image:
```
python3 DockerScanner.py metal3d/xmrig --critical --high
```
