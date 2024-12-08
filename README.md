<h1 align="center">PortRecon</h1>

<p align="center">
A high speed tool for passively gathering ports without active scanning.
</p>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/luqmanhy/portrecon"><img src="https://goreportcard.com/badge/github.com/luqmanhy/portrecon"></a>
<a href="https://github.com/luqmanhy/portrecon/releases"><img src="https://img.shields.io/github/release/luqmanhy/portrecon"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#postinstallation">Post Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> • 
  <a href="#credits">Credits</a> 
</p>

<p align="center">
<a href="https://github.com/luqmanhy/portrecon"><img src="/static/portrecon-demo.png" alt="PortRecon Demo"></a>
</p>

---

## Overview

Portrecon is a command-line tool designed to efficiently identify open ports for a given target. It gathers data from multiple passive sources, avoiding direct interaction with the target by relying on publicly available information. This makes Portrecon a practical tool for penetration testers, security researchers, and network administrators looking to understand exposed ports.


## Features
- Collects port data from multiple passive online sources for comprehensive results.
- Supports stdin and stdout for seamless integration into automated workflows.
- Provides service and version fingerprinting.
- Does not make any direct scan with the targets.
- Cross-platform support (Windows, Linux, and macOS).

## Installation
### Binaries
You can download a pre-built binary from [here](https://github.com/luqmanhy/portrecon/releases) and use it right away.

### Go
```sh
go install -v github.com/luqmanhy/portrecon/cmd/portrecon@latest
````

### Docker
To install `portrecon` on docker:

* Pull the docker image using:

    ```bash
    docker pull luqmanhy/portrecon:latest
    ```

* Run `portrecon` using the image:

    ```bash
    docker run --rm luqmanhy/portrecon:latest -h
    ```

## Post Installation

`portrecon` will work right after [installation](#installation). However, some sources require API keys to work. These keys can be added to the configuration file at `$HOME/.portrecon.yaml` or `%USERPROFILE%\.portrecon.yaml`, which will be created upon the first run.


Example of environment variables for API keys:

```bash
internetdb: true
shodan:
- shodan_key_1
- shodan_key_2
- shodan_key_3
criminalip:
- criminalip_key_1
- criminalip_key_2
- criminalip_key_3
binaryedge:
- binaryedge_key_1
- binaryedge_key_2
- binaryedge_key_3
```

## Usage
To start using `portrecon`, open your terminal and run the following command for a list of options:

```bash
portrecon -h
```

Here's what the help message looks like:

```
A powerful tool for passively gathering ports without active scanning.

USAGE:
 portrecon [flags]

FLAGS:
Input:
 -t <host>             scan a single ip/host
 -l <list_file>        scan multiple ip/hosts from a file

Options:
  -c <config_file>     flag config file (default $HOME/.portrecon.yaml or %USERPROFILE%\.portrecon.yaml)
  -s                   show only ip:port
  -v                   show verbose output
  -h                   display this help message
```

## Examples
### Basic 
```
portrecon -t 127.0.0.1
```
You can also use a list of targets, seperated by newlines.
```
portrecon -l ips.txt
```
**Supported formats**

```
1.1.1.1         // IPv4 address
example.com     // Hostname
```

## Tips

Portrecon collects existing port data from online sources, making it fast but there's more to it. You should consider validating the results with other tools.
### Validating using [Naabu](https://github.com/projectdiscovery/naabu)

```sh
portrecon -t example.com -s | naabu -s
```

## Credits
### Contributing

We welcome contributions! Feel free to submit [Pull Requests](https://github.com/luqmanhy/portrecon/pulls) or report [Issues](https://github.com/luqmanhy/portrecon/issues).

### Licensing

This utility is licensed under the [MIT license](https://opensource.org/license/mit). You are free to use, modify, and distribute it, as long as you follow the terms of the license. You can find the full license text in the repository - [Full MIT license text](https://github.com/luqmanhy/portrecon/blob/master/LICENSE).


### Similar Projects

If you're interested in more utilities like this, check out:

[smap](https://github.com/s0md3v/Smap) 