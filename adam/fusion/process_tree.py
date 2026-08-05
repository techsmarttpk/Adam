from __future__ import annotations

from dataclasses import dataclass, field

from .models import RawEvent


@dataclass(slots=True)
class ProcessNode:
    """
    Represents a process in the process tree.
    """

    pid: int
    name: str
    parent_pid: int | None
    children: set[int] = field(default_factory=set)


class ProcessTree:
    """
    Maintains parent-child relationships between processes.
    """

    def __init__(self):
        self.nodes: dict[int, ProcessNode] = {}

    def update(self, event: RawEvent) -> None:
        """
        Update the process tree using a process-related event.
        """

        if event.process_id is None:
            return

        pid = event.process_id
        parent = event.parent_process_id
        name = event.process_name or "Unknown"

        if pid not in self.nodes:
            self.nodes[pid] = ProcessNode(
                pid=pid,
                name=name,
                parent_pid=parent,
            )

        node = self.nodes[pid]

        node.name = name
        node.parent_pid = parent

        if parent is not None:

            if parent not in self.nodes:
                self.nodes[parent] = ProcessNode(
                    pid=parent,
                    name="Unknown",
                    parent_pid=None,
                )

            self.nodes[parent].children.add(pid)

    def get_process(self, pid: int) -> ProcessNode | None:
        """
        Return a process node by PID.
        """
        return self.nodes.get(pid)

    def get_children(self, pid: int) -> list[ProcessNode]:
        """
        Return all child processes.
        """
        node = self.nodes.get(pid)

        if node is None:
            return []

        return [
            self.nodes[child]
            for child in node.children
            if child in self.nodes
        ]

    def get_parent(self, pid: int) -> ProcessNode | None:
        """
        Return the parent process.
        """
        node = self.nodes.get(pid)

        if node is None:
            return None

        if node.parent_pid is None:
            return None

        return self.nodes.get(node.parent_pid)

    def get_ancestors(self, pid: int) -> list[ProcessNode]:
        """
        Return the ancestry of a process from parent to root.
        """
        ancestors: list[ProcessNode] = []

        current = self.get_parent(pid)

        while current is not None:
            ancestors.append(current)
            current = self.get_parent(current.pid)

        return ancestors

    def clear(self) -> None:
        """
        Remove all processes from the tree.
        """
        self.nodes.clear()

    def __len__(self) -> int:
        return len(self.nodes)