# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

class ConsensusStore:
    """
    A simple in-memory store to collect and manage consensus entries.
    """
    _data = []

    @classmethod
    def add(cls, entry):
        """
        Add a new entry to the store.

        Args:
            entry (Any): The item to add.
        """
        cls._data.append(entry)

    @classmethod
    def get_all(cls):
        """
        Retrieve all stored entries.

        Returns:
            list: All stored entries.
        """
        return cls._data

    @classmethod
    def clear(cls):
        """
        Clear all stored entries.
        """
        cls._data = []