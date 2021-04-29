# virus-scanner

Project for Computer Virus (SJTU-IS217) Group 6

[@Zihan Liu](https://github.com/zhliuworks), [@Zichao Xia](https://github.com/hxzd5568), [@Jinhao Li](https://github.com/ljh2000), [@Tianrui Chen](https://github.com/ctr-226), [@Yu Shao](https://github.com/Chinashaoyu)

### How to deploy

This project involves two separate parts, and we developed and tested in [UbuntuKylin](https://www.ubuntukylin.com/).

* MLscanner
* ClamAV GUI modification

The deployment process is as follows:

1. Install [ClamAV](https://www.clamav.net/documents/installing-clamav-on-unix-linux-macos-from-source) and [ClamTk](https://github.com/dave-theunsub/clamtk).
2. Install our MLscanner. Please refer to the Markdown in [`MLscanner/`](https://github.com/zhliuworks/virus-scanner/tree/main/MLscanner)
3. Move `GUI.pm` to `/usr/share/perl5/ClamTk`, and move `shield.png` to `/usr/share/pixmaps`. (`sudo chmod` is required)
4. Change Directory to `MLscanner/` ，run `clamtk` ，and our work has done.

<img src="https://github.com/zhliuworks/virus-scanner/blob/main/diagram.jpg" alt="diagram"/>