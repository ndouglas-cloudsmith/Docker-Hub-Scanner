# DockerHub Scanner
Unified Docker Hub scanner to check for the below information:
- Known Exploitable Vulnerabilities
- Intentionally Malicious Software Dependencies

```
wget https://raw.githubusercontent.com/ndouglas-cloudsmith/Docker-Hub-Scanner/refs/heads/main/DockerScanner.py
python3 DockerScanner.py
```

| Github Repos | Docker Hub | Malicious? | OSM Record |
| --- | --- | --- | --- |
|  | `d0whc3r/kali-ssh` | Yes | https://opensourcemalware.com/container/d0whc3r%2Fkali-ssh |
|  | `atlassian/confluence-server:7.13.6` | **No** | https://opensourcemalware.com/container/pmietlicki%2Fyada-miner |
|  | `metal3d/xmrig` | Yes | https://opensourcemalware.com/container/metal3d%2Fxmrig |
| github.com/wearenotpoliticallycorrect/docker-image |  | Yes | https://opensourcemalware.com/container/github.com%2Fwearenotpoliticallycorrect%2Fdocker-image |
| github.com/dvkunion/test_ci |  | Yes | https://opensourcemalware.com/container/github.com%2Fdvkunion%2Ftest_ci |
| github.com/ckmaenn/shello-2105 |  | Yes | https://opensourcemalware.com/container/github.com%2Fckmaenn%2Fshello-2105 |
|  | `cryptoandcoffee/nvidia-docker-meta-miner` | Yes | https://opensourcemalware.com/container/cryptoandcoffee%2Fnvidia-docker-meta-miner |
|  | `osekugatty/picture124` | Yes | https://opensourcemalware.com/container/osekugatty%2Fpicture124 |
|  | `021982/66_42_93_164` | Yes | https://opensourcemalware.com/container/021982%2F66_42_93_164 |

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
