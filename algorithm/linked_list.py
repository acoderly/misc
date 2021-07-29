# (1)Python实现双向链表类。
#
# (2)使用双向链表类实现基本的栈结构。
#
# (3)编写类表示二叉树，并实现二叉树的先序，中序，后序遍历的递归与非递归版本

class DoubleLinkedList:
    class Node:
        def __init__(self, data):
            self._data = data
            self._next = None
            self._pre = None

    def __init__(self):
        self.__head = DoubleLinkedList.Node("__head")
        self.__tail = DoubleLinkedList.Node("__tail")
        self.__head._next = self.__tail
        self.__tail._pre = self.__head

    def append(self, data):
        node = DoubleLinkedList.Node(data)
        self.__tail._pre._next = node
        node._pre = self.__tail._pre
        self.__tail._pre = node
        node._next = self.__tail

    def remove(self, data):
        node = self.__head
        while node != self.__tail:
            if node._data == data:
                node._pre._next = node._next
                node._next._pre = node._pre
                break
            node = node._next

    def insert(self, i, data):
        pass  # TODO 未实现insert操作

    def pop(self):
        node = self.__tail._pre
        if node != self.__head:
            node._pre._next = node._next
            node._next._pre = node._pre
            node._next = None
            node._pre = None
            return node._data
        return None

    def is_empty(self) -> bool:
        return self.__head._next == self.__tail

    def iternodes(self) -> None:
        node = self.__head._next
        while node != self.__tail:
            yield node._data
            node = node._next

    def add_last(self, data: object) -> None:
        self.append(data)

    def poll_first(self):
        node = self.__head._next
        if node != self.__tail:
            self.__head._next = node._next
            node._next._pre = self.__head
            node._next = None
            node._pre = None
            return node._data
        return None

    def poll_last(self):
        return self.pop()

    def peek_first(self):
        node = self.__head._next
        if node != self.__tail:
            return node._data
        return None

    def peek_last(self):
        node = self.__tail._pre
        if node != self.__head:
            return node._data
        return None


class Stack:
    def __init__(self):
        self.__dlnklst = DoubleLinkedList()

    def pop(self):
        return self.__dlnklst.pop()

    def add(self, data):
        self.__dlnklst.append(data)

    def push(self, data):
        return self.__dlnklst.append(data)

    def peek(self):
        return self.__dlnklst.peek_last()

    def poll(self):
        return self.__dlnklst.poll_last()

    def is_empty(self):
        return self.__dlnklst.is_empty()


class Node:
    def __init__(self, value):
        self.__value = value
        self.__left = None
        self.__right = None

    @property
    def value(self):
        return self.__value

    @property
    def left(self):
        return self.__left

    @left.setter
    def left(self, node):
        self.__left = node

    @property
    def right(self):
        return self.__right

    @right.setter
    def right(self, node):
        self.__right = node


def pre_order_recur(head):
    if not head:
        return
    print(head.value, sep=" ", end=" ")
    pre_order_recur(head.left)
    pre_order_recur(head.right)


def in_order_recur(head):
    if not head:
        return
    in_order_recur(head.left)
    print(head.value, sep=" ", end=" ")
    in_order_recur(head.right)


def post_order_recur(head):
    if not head:
        return
    post_order_recur(head.left)
    post_order_recur(head.right)
    print(head.value, sep=" ", end=" ")


# 先序非递归
def pre_order_unrecur(head):
    if not head:
        return
    stack = Stack()
    stack.add(head)
    while not stack.is_empty():
        head = stack.pop()
        print(head.value, sep=" ", end=" ")
        if head.right:
            stack.add(head.right)
        if head.left:
            stack.add(head.left)
    else:
        print()


# 中序非递归
def in_order_unrecur(head):
    if not head:
        return

    stack = Stack()

    while not stack.is_empty() or head:
        if head:
            stack.add(head)
            head = head.left
        else:
            head = stack.pop()
            print(head.value, sep=" ", end=" ")
            head = head.right

    else:
        print()


# 后序非递归
def post_order_unrecur(head):
    if not head:
        return

    stack1 = Stack()
    stack2 = Stack()
    stack1.add(head)

    while not stack1.is_empty():
        head = stack1.pop()
        stack2.add(head)
        if head.left:
            stack1.add(head.left)
        if head.right:
            stack1.add(head.right)

    while not stack2.is_empty():
        head = stack2.pop()
        print(head.value, sep=" ", end=" ")
    else:
        print()


if __name__ == "__main__":
    head = Node(1)
    head.left = Node(2)
    head.right = Node(3)
    head.left.left = Node(4)
    head.left.right = Node(5)
    head.right.right = Node(6)
    print("pre order travel binary tree.")
    pre_order_unrecur(head)
    pre_order_recur(head)
    print("\nIn order travel binary tree.")
    in_order_unrecur(head)
    in_order_recur(head)
    print("\nPost order travel binary tree.")
    post_order_unrecur(head)
    post_order_recur(head)
