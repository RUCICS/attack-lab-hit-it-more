# <center>栈溢出攻击实验</center>

## 题目解决思路


### Problem 1: 
**分析**：

```
栈溢出攻击改变输出的核心逻辑是：利用 func 中 strcpy 的无边界检查漏洞，覆盖 func 的返回地址，让程序执行完 func 后跳转到 func1（而不是回到 main），从而输出 func1 里的内容。
```

**解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片



**结果**：附上图片



### Problem 2:
- **分析**：...
- **解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片
- **结果**：附上图片

### Problem 3: 
- **分析**：...
- **解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片
- **结果**：附上图片

### Problem 4: 
- **分析**：体现canary的保护机制是什么
- **解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片
- **结果**：附上图片

## 思考与总结

首先lab里面给的都是二进制文件，我们首先要把他转成汇编文件`.asm`。

使用反汇编命令：

```
objdump -M intel -d problem1 > problem1.asm
```

然后就和Bomblab一样了：

```s
gdb problem1
```

手动构建输入可能比较累和不直观，可以用python程序构建答案：

```
python3 payload.py
```

构建完答案后尝试攻击：

```
./problem1 ans1.txt
```



## 参考资料

列出在准备报告过程中参考的所有文献、网站或其他资源，确保引用格式正确。
