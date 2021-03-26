# MLscanner

### Overview

Our scanner performs inference based on trained ML model. The training script is referred to [this](https://github.com/surajr/Machine-Learning-approach-for-Malware-Detection/blob/master/malware-classification.ipynb). Due to the limited dataset, the tool performs not that well but still works.

### Install

You need to install scikit-learn and [PyInstaller](https://github.com/pyinstaller/pyinstaller) before installing our tool.

```shell
pip install sklearn
pip install pyinstaller
```

Then,

```shell
git clone https://github.com/zhliuworks/virus-scanner.git
cd virus-scanner/MLscanner
make
```

Wait for a few minutes, `scanner` is installed in `dist/` and also we created a symbolic link in the current directory. And you can run the program in Linux with GUI like this :

```shell
./scanner
```

You can clear the installed binaries like this :

```shell
make clean
```