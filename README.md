<div id="top" align="center">
<h1>GH Repo Template</h1>

<p>Template for new Github repos</p>

[Report Issue](https://github.com/Zheng-Bote/repo-template/issues) [Request Feature](https://github.com/Zheng-Bote/repo-template/pulls)

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Zheng-Bote/repo-template?logo=GitHub)](https://github.com/Zheng-Bote/repo-template/releases)

</div>

<hr>

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Description](#description)
    - [Features](#features)
- [Status](#status)
    - [Documentation](#documentation)
      - [README](#readme)
      - [other Markdown files](#other-markdown-files)
- [Installation](#installation)
  - [Dependencies](#dependencies)
  - [folder structure](#folder-structure)
  - [Usage/Examples/Tests](#usageexamplestests)
- [API Reference](#api-reference)
  - [Inputs](#inputs)
  - [Outputs](#outputs)
  - [Parameters](#parameters)
- [Documentation](#documentation-1)
  - [Architecture](#architecture)
    - [Github](#github)
      - [Github Repo](#github-repo)
      - [Github Actions / Workflows](#github-actions--workflows)
  - [Application](#application)
  - [DevOps](#devops)
  - [Github Page](#github-page)
  - [Github Wiki](#github-wiki)
  - [Comments](#comments)
  - [Screenshots](#screenshots)
- [Authors and License](#authors-and-license)
  - [License](#license)
    - [MIT License](#mit-license)
    - [Apache License](#apache-license)
  - [Authors](#authors)
    - [Code Contributors](#code-contributors)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

<hr>

# Description

![QT](https://img.shields.io/badge/Community-6-41CD52?logo=qt)
![CXX](https://img.shields.io/badge/C++-20-blue?logo=cplusplus)
![Rust](https://img.shields.io/badge/Rust-Rocket-lightgrey?logo=rust)
![Expressif](https://img.shields.io/badge/ESP-32-E7352C?logo=espressif)
![GHA](https://img.shields.io/badge/Github-Action-black?logo=githubactions)
![Node](https://img.shields.io/badge/Node-20-blue?logo=tsnode)
![Angular](https://img.shields.io/badge/Angular-18+-red?logo=angular)
![Vue](https://img.shields.io/badge/Vue-3+-4FC08D?logo=vuedotjs)
![HTML5](https://img.shields.io/badge/HTML-5+-E34F26?logo=html5)
![Typescript](https://img.shields.io/badge/TypeScript-5+-3178C6?logo=typescript)
![Svelte.js](https://img.shields.io/badge/Svelte-5-324FFF?logo=svelte)
![Lit.js](https://img.shields.io/badge/Lit.js-324FFF?logo=lit)
![CSS3](https://img.shields.io/badge/CSS-663399?logo=css3)

Repo template with README-template and some Github workflows and Github actions.

### Features

- \[ ] advanced-super-extra-special feature xyz

  <br>
  
- \[x] OSS and license
- \[x] works as designed
- \[ ] no bugs

<br>

- \[x] some more or less usefull Github Actions for GH-repo, GH-pages, GH-wiki, CI/CD-Pipelines
- \[ ] Packagemanager
- \[ ] Installation routine
- \[ ] portable application 

<br>

- \[ ] runs on DOS/Windows
- \[ ] runs on MacOS
- \[ ] runs on Linux
- \[ ] runs on iOS
- \[ ] runs on Android
- \[ ] runs on HarmonyOS


<p align="right">(<a href="#top">back to top</a>)</p>

# Status

:arrow_right: <mark>:warning: still under construction :warning:</mark> :arrow_left:

![GitHub Created At](https://img.shields.io/github/created-at/Zheng-Bote/repo-template)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Zheng-Bote/repo-template?logo=GitHub)](https://github.com/Zheng-Bote/repo-template/releases)
![GitHub Release Date](https://img.shields.io/github/release-date/Zheng-Bote/repo-template)
![Status](https://img.shields.io/badge/Status-stable-green)
![Status](https://img.shields.io/badge/Status-under_construction-red)
![Status](https://img.shields.io/badge/Status-works_as_designed-green)

![GitHub Created At](https://img.shields.io/github/created-at/Zheng-Bote/repo-template)
![GitHub Release Date](https://img.shields.io/github/release-date/Zheng-Bote/repo-template)

![GitHub Issues](https://img.shields.io/github/issues/Zheng-Bote/repo-template)
![GitHub Pull Requests](https://img.shields.io/github/issues-pr/Zheng-Bote/repo-template)

### Documentation

_see also:_ [Application Documentation](#documentation) 

#### README
[![Repo - create Repo-Tree in README.md](https://github.com/Zheng-Bote/repo-template/actions/workflows/repo-create_tree_readme.yml/badge.svg)](https://github.com/Zheng-Bote/repo-template/actions/workflows/repo-create_tree_readme.yml)
[![Repo - add Actions In/Out to README](https://github.com/Zheng-Bote/repo-template/actions/workflows/repo-actions_docu.yml/badge.svg)](https://github.com/Zheng-Bote/repo-template/actions/workflows/repo-actions_docu.yml)

[![Repo - update Readme](https://github.com/Zheng-Bote/repo-template/actions/workflows/repo-call_Readme.yml/badge.svg)](https://github.com/Zheng-Bote/repo-template/actions/workflows/repo-call_Readme.yml)

#### other Markdown files

[![Repo - create TOC of Markdown files](https://github.com/Zheng-Bote/repo-template/actions/workflows/repo-create_doctoc_md.yml/badge.svg)](https://github.com/Zheng-Bote/repo-template/actions/workflows/repo-create_doctoc_md.yml)

create ToC in Markdown files in folders

- .github/actions/\*\*
- .github/workflows/\*\*
- dist/\*\*
- docs/\*\*

<p align="right">(<a href="#top">back to top</a>)</p>

# Installation

bla bla ... everything easy and green with No Code/Low code and without any costs

## Dependencies

bla bla ... with a little help from my friends

## folder structure

<!-- readme-tree start -->
```
.
├── .github
│   ├── actions
│   │   └── doctoc
│   │       ├── README.md
│   │       ├── action.yml
│   │       └── dist
│   │           ├── index.js
│   │           ├── index.js.map
│   │           ├── licenses.txt
│   │           └── sourcemap-register.js
│   └── workflows
│       ├── ghp-call_Readme.yml
│       ├── ghp-create_doctoc.yml
│       ├── ghp-markdown_index.yml
│       ├── repo-actions_docu.yml
│       ├── repo-call_Readme.yml
│       ├── repo-create_doctoc.yml_
│       ├── repo-create_doctoc_md.yml
│       └── repo-create_tree_readme.yml
├── LICENSE
├── LICENSE_Apache-2
├── LICENSE_GPL-2
├── LICENSE_GPL-3
├── LICENSE_MIT
├── README.md
└── tree.bak

6 directories, 21 files
```
<!-- readme-tree end -->

<p align="right">(<a href="#top">back to top</a>)</p>

## Usage/Examples/Tests

bla bla ... usage is intuitive and runs mostly automatically with no needs of any knowledge

```HTML
<mark> under construction </mark>
```

<p align="right">(<a href="#top">back to top</a>)</p>

# API Reference

<hr>

![GHA](https://img.shields.io/badge/Github-Action-black?logo=githubactions)

_Inputs/Outputs will be filled automatically by `.github/workflows/repo-actions_docu.yml`_

## Inputs

## Outputs

<hr>

<p align="right">(<a href="#top">back to top</a>)</p>

## Parameters

**Workflow or program**

| Parameter    | Type     | Description                          |
| :----------- | :------- | :----------------------------------- |
| `name`       | `string` | _Optional_ name-of-copyright-holder  |
| `created`    | `string` | _Optional_ <YYYY>                    |
| `version`    | `string` | _Optional_ \<v0.0.0>                 |
| `link_left`  | `string` | _Optional_ link-to-contact-page      |
| `link_right` | `string` | _Optional_ link-to-legal-notice-page |

<p align="right">(<a href="#top">back to top</a>)</p>

# Documentation

see also: <https://linktodocumentation>

## Architecture

### Github

#### Github Repo

```mermaid
block-beta
  columns 4
  Repo:4
  block:group1:1
    columns 1
    id0[".github"]
    block:group2:1
      columns 1
      id1[["workflows"]]
      id2[["actions"]]
    end
  end
  docs dist src
  block:group3:4
    %% columns auto (default)
    A["gh-pages"] B["gh-wiki"]
  end
```

#### Github Actions / Workflows

```mermaid
flowchart TD;
    A[Workflow]-. parameter .->B[[callable Workflow]]
    B-- parameter -->C[Action]
    C-->D(README)

    A[Workflow]-. parameter .->E[[callable Workflow]]
    E-- parameter -->F[Action]
    F-->J(Markdown files)

    A[Workflow]-->K[[Workflow]]
    K-->L[Action]
    L-->M("GH-Pages")

    A[Workflow]-->N[[Workflow]]
    N-->O[Action]
    O-->P("GH-Wiki")
```

<p align="right">(<a href="#top">back to top</a>)</p>

## Application

```mermaid
architecture-beta
    group api(cloud)[API]

    service db(database)[Database] in api
    service server0(server)[Webserver] in api
    service disk2(disk)[Storage] in api
    service server(server)[Appserver] in api

    db:L -- R:server
    server0:T -- B:server
    disk2:T -- B:server
```

## DevOps

```mermaid
pie title me
         "ideas" : 90
         "time for realizations" : 7
         "money for realizations" : 3
```

<p align="right">(<a href="#top">back to top</a>)</p>

## Github Page

[![GH-Page](https://img.shields.io/badge/Github-Pages-black?logo=github)](https://www.github.com/Zheng-Bote)

## Github Wiki

[![GH-Wiki](https://img.shields.io/badge/Github-Wiki-black?logo=github)](https://www.github.com/Zheng-Bote)

## Comments

> \[!NOTE]
> Useful information that users should know, even when skimming content.

> \[!TIP]
> Helpful advice for doing things better or more easily.

> \[!IMPORTANT]
> Key information users need to know to achieve their goal.

> \[!WARNING]
> Urgent info that needs immediate user attention to avoid problems.

> \[!CAUTION]
> Advises about risks or negative outcomes of certain actions.

<p align="right">(<a href="#top">back to top</a>)</p>

## Screenshots

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

<p align="right">(<a href="#top">back to top</a>)</p>

# Authors and License

## License

**This Repo-Template is using the MIT-License**

**_other licenses see files `LICENSE_<name>`\_**

### MIT License

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

Copyright (c) 2024 ZHENG Robert

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

        https://choosealicense.com/licenses/mit/

### Apache License

[![Apache License](https://img.shields.io/badge/License-Apache_v2.0-green.svg)](<[https://choosealicense.com/licenses/mit/](http://www.apache.org/licenses/LICENSE-2.0)>)

Copyright (c) 2019 ZHENG Robert

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and limitations under the License.

## Authors

- [![Zheng Robert](https://img.shields.io/badge/Github-Zheng_Robert-black?logo=github)](https://www.github.com/Zheng-Bote)

### Code Contributors

![Contributors](https://img.shields.io/github/contributors/Zheng-Bote/repo-template?color=dark-green)

[![Zheng Robert](https://img.shields.io/badge/Github-Zheng_Robert-black?logo=github)](https://www.github.com/Zheng-Bote)

<hr>

:vulcan_salute:

<p align="right">(<a href="#top">back to top</a>)</p>
