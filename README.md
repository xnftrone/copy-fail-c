# copy-fail-c
c语言重写的轻量copyfail利用脚本

## 文件结构
```
copy_fail_exp_splice.c
copy_fail_exp_sendfile.c
```

针对pipe+slice和sendfile两种利用方法都做了重写，sendfile版本**可能**能在更老的内核版本上运行（未测试）

## 编译
```
gcc -Wall -Wextra -std=gnu11 copy_fail_exp.c -lz -o copy_fail_exp
```

静态链接
```
gcc -Wall -Wextra -std=gnu11 copy_fail_exp.c -static -lz -o copy_fail_exp_static
```
