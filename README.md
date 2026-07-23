# DockerHub Scanner
Unified Docker Hub scanner to check for the below information:
- Known Exploitable Vulnerabilities
- Intentionally Malicious Software Dependencies

```
wget https://raw.githubusercontent.com/ndouglas-cloudsmith/Docker-Hub-Scanner/refs/heads/main/DockerScanner.py
python3 DockerScanner.py
```

| Docker Images | Malicious? | OSM Record | Exploited? |
| --- | --- | --- | --- |
| `d0whc3r/kali-ssh` | Yes | https://opensourcemalware.com/container/d0whc3r%2Fkali-ssh |  |
| `atlassian/confluence-server:7.13.6` | **No** |  | **Yes** |
| `metal3d/xmrig` | Yes | https://opensourcemalware.com/container/metal3d%2Fxmrig |  |
| `solr:8.11.0` | **No** |  | **Yes** |
| github.com/wearenotpoliticallycorrect/docker-image | Yes | https://opensourcemalware.com/container/github.com%2Fwearenotpoliticallycorrect%2Fdocker-image |  |
| github.com/dvkunion/test_ci | github.com/dvkunion/test_ci | Yes | https://opensourcemalware.com/container/github.com%2Fdvkunion%2Ftest_ci |  |
| github.com/ckmaenn/shello-2105 | github.com/ckmaenn/shello-2105 | Yes | https://opensourcemalware.com/container/github.com%2Fckmaenn%2Fshello-2105 |  |
| `cryptoandcoffee/nvidia-docker-meta-miner` | Yes | https://opensourcemalware.com/container/cryptoandcoffee%2Fnvidia-docker-meta-miner |  |
| `osekugatty/picture124` | Yes | https://opensourcemalware.com/container/osekugatty%2Fpicture124 |  |
| `vulhub/activemq:5.16.5` | **No** |  | **Yes** |
| `021982/66_42_93_164` | Yes | https://opensourcemalware.com/container/021982%2F66_42_93_164 |  |

## Sample Commands

You can run the script directly with positional arguments or fall back to interactive prompt (if omitted). <br/>
Scan for a specific docker container called ```metal3d/xmrig``` with a bunch of different flags listed below:
```
python3 DockerScanner.py metal3d/xmrig
```
Find only ```HIGH``` CVEs for a specific image:
```
python3 DockerScanner.py vulhub/activemq:5.16.5 --high
```
Find only ```CRITICAL``` CVEs for a specific image:
```
python3 DockerScanner.py solr:8.11.0 --critical
```
Find ```HIGH``` and ```CRITICAL``` CVEs for the same container image:
```
python3 DockerScanner.py metal3d/xmrig --critical --high
```
Filter for Known Exploited Vuklnerabilities (**[KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)**) using the ```--kev``` flag:
```
python3 DockerScanner.py vulhub/activemq:5.16.5 --high --kev 
```
Sort High severity findings by **[EPSS](https://www.first.org/epss/) descending**:
```
python3 DockerScanner.py vulhub/activemq:5.16.5 --high --epss-dec
```
Combine ```EPSS``` scores in descending order and ```KEV``` filtering:
```
python3 DockerScanner.py vulhub/activemq:5.16.5 --high --kev --epss-desc
```
Combine ```CVSS``` scores in descending order, where a **[CWE](https://cwe.mitre.org/data/pdfs.html)** *MUST* be present:
```
DockerScanner.py vulhub/activemq:5.16.5 --critical --cvss-desc --cwe-true
```
Included a ```--verbose``` flag that describes the significance of the CWE:
```
python3 DockerScanner.py vulhub/activemq:5.16.5 --critical --high --cvss-desc --cwe-true --verbose
```
Included an ```--exploitdb``` flag that lets the user know if an Known Exploited Vulnerability has an associated, public-facing exploit script in the **[ExploitDB](https://www.exploit-db.com/exploits/52479)** database.
```
python3 DockerScanner.py vulhub/activemq:5.16.5 --critical --high --epss-desc --kev --exploitdb
```
