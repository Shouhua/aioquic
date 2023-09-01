import sys
# sys.path.append('foo')
print(list(sys.path))
import foo

print(foo.foo_add(1, 2))