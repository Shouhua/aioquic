# [Bourne-Again Shell(bash)](https://www.gnu.org/software/bash/manual/bash.html#Invoking-Bash)
[Bash是GNU项目的一部分，是大部分Linux系统的交互shell](https://en.wikipedia.org/wiki/Unix_shell)。本文主要是阅读文档后的总结，结构类似，添加大量实例验证文档。

## Definitions
- control operator: new line, '||', '&&', '&', ';', ';;', ';&', ';;&', '|', '|&', '(', ')'
- operator: control operators and redirect operator

**主要用于shell command语句分割, 包括[simple command](https://www.gnu.org/software/bash/manual/bash.html#Simple-Commands)还有[Lists of Commands]https://www.gnu.org/software/bash/manual/bash.html#Lists)，然后[处理分割后的语句，比如各种expansion等](https://www.gnu.org/software/bash/manual/bash.html#Executing-Commands)**，这个重要，可以解释很多场景

## Shell Syntax -> Shell Quoting
### ANSI-C Quoting
**`$'string'`**主要用于解析string里面的backslash escape sequences, 比如：`sort -r <<< $'a\nb\nc`，这里注意redirection，`< word` 中word是文件描述符，如果我们要显式的redirection文档或者字符串，可以使用`<<`和`<<<`，比如这里这样`sort -r < $'a\nb\nc'`就不正确

## Shell Command
### Simple Commands
**[A simple command is just a sequence of words seperated by blanks, terminated by one of the shell's control operators](https://www.gnu.org/software/bash/manual/bash.html#Simple-Commands)**，写的真好，定义了分割语句的规则

### Grouping Commands
- `( list )` create **subshell** to execute list
- `{ list; }` the semicolon following list is required

### Coprocesses
TODO

## Shell Functions
1. syntax
```bash
fname () compound-command [ redirections ] 
or
function fname [()] compound-command [ redirections ] 
```
2. scope
- 默认function里面的变量，调用函数后，函数外是能访问到的
- local声明的变量，只在自己和子函数中可见
3. return
正常情况下，函数的返回状态是最后一个命令的exit status；如果有`return [number]`则为number，如果return的其他类型，则还是最后一个命令的exit status

## Shell Parameters
`name=[value]`
`declare -i a=1+1` (这种情况下会触发arithmetic expansion)
`delare -n ref=$1`
`unset name`
### Positional Parameters
1. 当shell被执行时，positional parameter就会被shell's arguments填充，**set也可以重新给他们赋值**
2. `$0, $1 .. ${10}, ${11}`，当个数超过一位数时，需要使用`{}`包裹
3. `set`和`shift`都可以设置和移除positional parameter
```bash
set -- hello world # 此时$1="hello" $2="world"
shift [n] # 左移n个参数，参数会被重新赋值，比如shift 2后，$1'=$3
```
### Special Parameters
1. `$*`和`$@`
- `$*`和`$@`都是根据IFS划分传入的参数
- `"$*"`根据IFS的第一个字符将传参连成一个字符串；`"$@"`每个传参都是独立的个体，当然还会进行各种expansion，一般情况使用`"$@"`
```bash
IFS=A; set -- helloAworld again; echo $@ # hello world again
IFS=A; set -- helloAworld again; echo $* # hello world again

# "$*"="$1c$2c.."
IFS=A; set -- helloAworld again; echo "$*" # "helloAworldAagain"
# "$@"="$1" "$2"
IFS=A; set -- helloAworld again; echo "$@" # "helloAworld" "again"
```
IFS默认值为space, tab, newline
```shell
declare -p IFS # 查看IFS变量定义
echo "$IFS" | hexdump -C # 0x20 0x09 0x0a
cat -A <<< "$IFS"
set -- helloAworld again
IFS="A"; for v in $@; do echo $v; done
```
2. 其他
```bash
# `$#` the number of positional parameter
# `$?` exit status; `$$` 
# $- 当前set的options，比如可以查看支持哪些扩展属性，比如是否支持history ！
# $$ 当前shell的process id，子进程使用$BASHID才是准确的
# $! 最近的job的process id，即background的id
# $0 shell脚本名称
```
## Shell Expansion
