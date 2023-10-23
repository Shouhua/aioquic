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

### Compound Commands
1. Looping Constructs<br>
`for (( expr1; expr2; expr3; )); do commands; done`
2. Conditional Constructs<br>
**`(( expression ))`跟`$(( expression ))`区别，通俗讲前者在执行命令，可以放在shell脚本中单独一行，后者常用语赋值语句或者double quote中；有3中方式执行arithmetic：`(( expression ))`, `let expr1 expr2`, `delcare -i name=expression`**
3. Grouping Commands<br>
- `( list )` create **subshell** to execute list
- `{ list; }` the semicolon following list is required

## Shell Functions
1. syntax
```bash
fname () compound-command [ redirections ] 
or
function fname [()] compound-command [ redirections ] 
```
2. scope
- 默认function里面的变量，调用函数后，函数外是能访问到的
- local声明的变量，只在自己和子函数中可见; **在函数中使用declare声明变量可以只能在本函数中使用, 详见declare解释中举例说明**
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
set -- helloAworld again
IFS=A echo $@ # hello world again
IFS=A echo $* # hello world again

# "$*"="$1c$2c.."
IFS=A echo "$*" # "helloAworldAagain"
# "$@"="$1" "$2"
IFS=A echo "$@" # "helloAworld" "again"
```
- `"$@"`还有个特殊情况，自动把首位和尾部join起来，比如[`set -- "ted carol" "alice bob"; printf "%s\n" "hello $@ world"`](https://stackoverflow.com/questions/27808730/word-splitting-happens-even-with-double-quotes)，这里对应了文档里面的一句话，
[`If the double-quoted expansion occurs within a word, the expansion of the first parameter is joined with the beginning part of the original word, and the expansion of the last parameter is joined with the last part of the original word`](https://www.gnu.org/software/bash/manual/bash.html#Positional-Parameters)

**IFS默认值为space, tab, newline**
```shell
declare -p IFS # 查看IFS变量定义
echo "$IFS" | hexdump -C # 0x20 0x09 0x0a
cat -A <<< "$IFS"
set -- helloAworld again
IFS="A"; for v in $@; do echo $v; done
# TODO: 为什么以下语句会报错 bash: syntax error near unexpected token `do'
IFS="A" for v in $@; do echo $v; done
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
there are seven kinds of expansion performed:
- brace expansion
- tidle expansion
- parameter and variable expansion
- arithmetic expansion
- process substitution(*)
- command substitution
- word splitting
- filename expansion

### Brace Expansion
```shell
bash -c 'echo a{b,c,d}e'
# {x..y[..incr]} x and y are either int or letters, incr int
bash -c 'echo {z..h..-2}'
bash -c 'echo /usr/{ucb/{ex,edit},lib/{ex?.?*,how_ex}}' # /usr/ucb/ex /usr/ucb/edit /usr/lib/ex?.?* /usr/lib/how_ex
```

### tidle expansion
```
~ = $HOME
~+ = $PWD
~- = $OLDPWD
~fred/foo The subdirectory foo of the home directory of the user fred
```

### shell parameter expansion
syntax: ${parameter}, ${!parameter} indirect expansion, except ${!prefix*} and ${!name[@]}
```bash
var=hello hello=world; echo ${!var} # world
echo ${!LC*} # print all LC prefixed variable
declare -A arr=([name]=James [age]=38); echo ${!arr[@]} # print array keys
```

1. 变量测试替换，如果有 ":" 表示除了测试variable 是不是unset的状态外，还要测试是否为null
```bash
var="hello"; echo ${var-unset} # hello
var=;: ${var:=DEFAULT}; echo $var # DEFAULT
var=;: ${var:?var is unset or null} # bash: var: var is unset or null
var=123; echo ${var:+var is set and not null} # var is set and not null
```
**NOTE: `":"` [POSIX builtin，代表true，true是`/usr/bin/true`，会忽略所有参数，但是参数会各种expansion，返回0, 这里可以快速的执行 parameter expansion而不用其他操作](https://stackoverflow.com/questions/3224878/what-is-the-purpose-of-the-colon-gnu-bash-builtin)**  

还可以变相的使用上述实现测试变量是否为unset或者null
```bash
# [[ -e var ]]
if [[ ${var:1} -eq 1 ]]; then echo "var is not set"; else echo "var is set"; fi;
```

2. 变量substring expansion
syntax: 
- `${parameter:offset[:length]}`, 截取变量值
- `${!prefix@} ${!prefix*}`, 返回以prefix开头的变量名称列表
- `${!name[@]} ${!name[*]}`, 返回keys of indexed or associated array
- `${#parameter}`, 返回变量值长度
- `${parameter#word} ${parameter##word}`, 删除变量值以word匹配的开头部分, # 最短匹配 ## 最长匹配
- `${parameter%word} ${parameter%%word}`, 删除变量值以word匹配的结尾部分, % 最短匹配 %% 最长匹配
- `${parameter/pattern/string} ${parameter//pattern/string}`, 替换变量值里面pattern匹配的地方, / 匹配第一处 // 全局替换 
- `${parameter/#pattern/string} ${parameter/%pattern/string}`, 变量值匹配开头/尾部pattern
- `${parameter^pattern} ${parameter^^pattern}`, 匹配pattern部分大写，如果没有pattern, 大写首字母或者全部大写
- `${parameter~pattern} ${parameter~~pattern}`, reverse string case
- `${parameter,pattern} ${parameter,,pattern}`, 匹配pattern部分小写，如果没有pattern, 小写首字母或者全部小写
- [${parameter@operator}](https://stackoverflow.com/questions/40732193/bash-how-to-use-operator-parameter-expansion-parameteroperator), 根据operator操作值

### Command Substitution
syntax: `$(command)` or `` `command` ``

**use \$(< file) instead of \$(cat file), because the former is faster**

### Arithmetic Expansion
syntax: `$(( expression ))`

### [Process Substitution](https://tldp.org/LDP/abs/html/process-sub.html)
看文档主要是如果需要从多个进程读取为输入，可以使用这种方式，比如：comm, diff等，当然如果只有一个也是能胜任的
```bash
while read line;do
  let num2+=1
  echo $num2: $line
done < <(sleep 10; grep 'UUID' /etc/fstab)
```
## Redirections
&>fd equals to >fd 2>&1

### here document
```bash
eval $'cat <<-"EOF" > test.txt\n\thome:$OLDPWD\nEOF'
```
1. **如果EOF有引号，内容不会展开 test.txt内容为home: $HOME;**
2. **<<-会清除leading spaces**

### here string
`cat <<< ~ # /home/shouhua`

## Executing Commands
### simple command expansion(https://www.gnu.org/software/bash/manual/bash.html#Simple-Command-Expansion)
1. 先保存variable assignment和redirections
2. 其余部分各种expansion，确定command and arguments
3. perform redirections
4. 对赋值语句的value执行各种expansion
5. execute command，shell func, builtins, $PATH
6. execute env

### Command Search and Execution
查找command顺序
1. 如果没有没有包括slash, 查找shell function
2. shell builtin
3. $PATH
4. shell

## Bourne Shell Builtins
- `: [arguments]` alway return zero, do nothing beyond expanding arguments and performing redirections
- `brean [n]` or `continue [n]` n>=1 默认n=1，如果n>1，用于退出第n层loop，从当前层开始
- `trap [-lp] [arg] [sigspec ...]`
## Bourne-Again Shell Builtins
- `declare [-aAfFgiIlnrtux] [-p] [name[=value] ...]` -r readonly, -i integer, -a array, -f function, -x exportable.
```
-a indexed array
-A associated array
-f function name only
-i integer
-l convert value to lowercase
-n nameref
-r readonly
-u convert value to uppercase
-x export variable
```
**[还可以缩小函数变量的scope](https://tldp.org/LDP/abs/html/declareref.html)**
```bash
foo (){
declare FOO="bar"
}

bar ()
{
foo
echo $FOO
}

bar  # Prints nothing.
```
- `type [-afptP] [name ...]` `-t` print single word which is one of 'alias', 'fucntion', 'builtin', 'file' or 'keyworkd'

## Modify Shell Behavior
### set
1. change value of shell options
2. set the positional parameters
3. display the names and values of shell variables

## Bash Variables
- BASHPID, BASHCOMMAND, BASH_LINENO

## NOTE
1. 条件语句比如if，else等，条件测试返回0时进入if，其他进入else
2. -v varname 测试var是否set，还可以使用parameter expansion判断
if [[ -z ${varname+x} ]]; then echo "varname is unset"; else echo "varname is ${varname}"; fi
${varname:+x} vs ${varname+x} 相同点是只有当varname被set时才会使用x调换，否则为varname；":"除了test unset外，还会test是否为空
3. 单行语句包括赋值和变量相关引用注意。一般我们会遇到如下几种，总体的解决思路就是shell执行步骤：
```bash
# 1. 直接引用，这种在shell执行第二步，expand除赋值和redirection语句外的word, $var被解析为以前的值，因为var=hello等到下一步才进行
var=world
var=hello echo "$var" # world

# 2. 相比较1来说，locale执行时才调用LANG变量，这个时候LANG赋值已经执行完成
LANG='en_US.UTF-8'
LANG='zh_CN.UTF-8' locale # locale中没有值的都为新的'zh_CN.UTF-8'
# 类似的，常用的IFS赋值
set -- helloAworld again
IFS=A echo "$*" # helloAworldAagain
# 3. shell commands里面介绍了simple command的分类，&& 后面应该会重新走command expansion流程(https://www.gnu.org/software/bash/manual/bash.html#Shell-Operation)
var=hello && echo $var # &&是control operator
```
4. sleep 60s 会生成新的sleep进程，可以使用ps -ef | grep [pid] 查看
5. set -o [emacs|vi] # command line editting
6. cat -A -n < /etc/passwd
7. here string 可以代替管道前的echo
grep "llo" <<< "hello world"
8. IFS 
1). 在变量替换 (扩展)、命令替换 (扩展)、算术替换 (扩展) 时，如果它们的结果没有使用引号包围，则尝试使用 IFS 将结果进行单词划分
2). 在 read 命令中，根据 IFS 将所读取的内容划分为单词分别赋值给指定的变量
9. bash执行进度动画 https://www.junmajinlong.com/shell/shell_perl_gif/
10. 随机数
bash中有2个相关变量`RANDOM`和`SRANDOM`, `SRANDOM`用于设置seed，如果每次设置同一个值，那么调用`$RANDOM`产生的数据都是一样的顺序打印出，`$RANDOM`使用16位数据，[0-32767]
命令行或者脚本中可以使用这2个变量产生随机数，也可以使用awk提供的类似C的函数，如下例所示，不同的是`rand`产生的随机数区间为[0-1]
C语言中使用函数`srandom`和`random`，区间为：[0 - 2^31-1]
python中random函数也是[0-1]
```bash
# https://tldp.org/LDP/abs/html/randomvar.html
awk_script='{for(i=0;i<10;i++){srand(seed i); print int(rand()*90+10)}}'
echo | awk -v seed=$RANDOM $awk_script
```