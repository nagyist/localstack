# TODO, for now, this file will contain only files for the new S3 provider but not compatible with persistence
# it will then put in the other models file?
# do something specific in the persistence file?
import sys
from typing import Iterator

# TODO: beware of timestamp data, we need the snapshot to be more precise for S3, with the different types
# moto had a lot of issue with it? not sure about our parser/serializer

# for persistence, append the version id to the key name using a special symbol?? like __version_id__={version_id}


# TODO: we will need a versioned key store as well, let's check what we can get better
class S3Bucket:
    multiparts: dict
    objects: dict  # TODO: change

    # set all buckets parameters here
    # first one in moto, then one in our provider added (cors, lifecycle and such)
    pass


class S3Object:
    pass


class S3DeleteMarker:
    pass


class S3Multipart:
    pass


class S3Part:
    pass


class _VersionedKeyStore(dict):  # type: ignore

    """A modified version of Moto's `_VersionedKeyStore`"""

    def __sgetitem__(self, key: str) -> list[S3Object | S3DeleteMarker]:
        return super().__getitem__(key)

    def pop(self, key: str) -> None:
        for version in self.getlist(key, []):
            version.dispose()
        super().pop(key)

    def __getitem__(self, key: str) -> S3Object | S3DeleteMarker:
        return self.__sgetitem__(key)[-1]

    def __setitem__(self, key: str, value: S3Object | S3DeleteMarker) -> None:
        try:
            current = self.__sgetitem__(key)
            current.append(value)
        except (KeyError, IndexError):
            current = [value]

        super().__setitem__(key, current)

    def get(self, key: str, default: S3Object | S3DeleteMarker = None) -> S3Object | S3DeleteMarker:
        try:
            return self[key]
        except (KeyError, IndexError):
            pass
        return default

    def setdefault(
        self, key: str, default: S3Object | S3DeleteMarker = None
    ) -> S3Object | S3DeleteMarker:
        try:
            return self[key]
        except (KeyError, IndexError):
            self[key] = default
        return default

    def getlist(
        self, key: str, default: list[S3Object | S3DeleteMarker] = None
    ) -> list[S3Object | S3DeleteMarker]:
        try:
            return self.__sgetitem__(key)
        except (KeyError, IndexError):
            pass
        return default

    def setlist(self, key: str, _list: list[S3Object | S3DeleteMarker]) -> None:
        if isinstance(_list, tuple):
            _list = list(_list)
        elif not isinstance(_list, list):
            _list = [_list]

        for existing_version in self.getlist(key, []):
            # Dispose of any FakeKeys that we will not keep
            # We should only have FakeKeys here - but we're checking hasattr to be sure
            if existing_version not in _list and hasattr(existing_version, "dispose"):
                existing_version.dispose()

        super().__setitem__(key, _list)

    def _iteritems(self) -> Iterator[tuple[str, S3Object | S3DeleteMarker]]:
        for key in self._self_iterable():
            yield key, self[key]

    def _itervalues(self) -> Iterator[S3Object | S3DeleteMarker]:
        for key in self._self_iterable():
            yield self[key]

    def _iterlists(self) -> Iterator[tuple[str, list[S3Object | S3DeleteMarker]]]:
        for key in self._self_iterable():
            yield key, self.getlist(key)

    def item_size(self) -> int:
        size = 0
        for val in self._self_iterable().values():
            # TODO: not sure about that, especially storage values from tempfile?
            # Should we iterate on key.size instead? and on every version? because we don't store diff or anything?
            # not sure
            size += sys.getsizeof(val)
        return size

    def _self_iterable(self) -> dict[str, S3Object | S3DeleteMarker]:
        # TODO: locking
        #  to enable concurrency, return a copy, to avoid "dictionary changed size during iteration"
        #  TODO: look into replacing with a locking mechanism, potentially
        return dict(self)

    items = iteritems = _iteritems  # type: ignore
    lists = iterlists = _iterlists
    values = itervalues = _itervalues  # type: ignore
