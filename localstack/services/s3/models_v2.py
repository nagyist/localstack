# TODO, for now, this file will contain only files for the new S3 provider but not compatible with persistence
# it will then put in the other models file?
# do something specific in the persistence file?
from datetime import datetime
from tempfile import SpooledTemporaryFile
from typing import Iterator, Optional

from localstack import config
from localstack.aws.api.s3 import (
    AnalyticsConfiguration,
    AnalyticsId,
    BucketAccelerateStatus,
    BucketName,
    ChecksumAlgorithm,
    CORSConfiguration,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    LifecycleRules,
    LoggingEnabled,
    NotificationConfiguration,
    ObjectLockConfiguration,
    ObjectLockLegalHoldStatus,
    ObjectLockMode,
    ObjectOwnership,
    Payer,
    Policy,
    PublicAccessBlockConfiguration,
    ReplicationConfiguration,
    ServerSideEncryption,
    ServerSideEncryptionRules,
    SSEKMSKeyId,
    StorageClass,
    WebsiteConfiguration,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute

# TODO: beware of timestamp data, we need the snapshot to be more precise for S3, with the different types
# moto had a lot of issue with it? not sure about our parser/serializer

# for persistence, append the version id to the key name using a special symbol?? like __version_id__={version_id}

# TODO: we need to make the SpooledTemporaryFile configurable for persistence?


# TODO: we will need a versioned key store as well, let's check what we can get better
class S3Bucket:
    account_id: str
    region_name: str
    creation_date: datetime
    multiparts: dict
    objects: "_VersionedKeyStore"
    versioning_status: bool
    lifecycle_rules: LifecycleRules
    policy: Policy
    website_configuration: WebsiteConfiguration
    acl: str  # TODO: change this
    cors_rules: CORSConfiguration
    logging: LoggingEnabled
    notification_configuration: NotificationConfiguration
    payer: Payer
    encryption_rules: ServerSideEncryptionRules
    public_access_block: PublicAccessBlockConfiguration
    accelerate_status: BucketAccelerateStatus
    object_ownership: ObjectOwnership
    object_lock_configuration: Optional[ObjectLockConfiguration]
    object_lock_enabled: bool
    intelligent_tiering_configuration: dict[IntelligentTieringId, IntelligentTieringConfiguration]
    analytics_configuration: dict[AnalyticsId, AnalyticsConfiguration]
    replication: ReplicationConfiguration

    # set all buckets parameters here
    # first one in moto, then one in our provider added (cors, lifecycle and such)
    pass


class S3Object:
    value: SpooledTemporaryFile  # TODO: locking
    key: str
    version_id: Optional[str]
    size: int
    etag: str
    metadata: dict[str, str]  # TODO: check this?
    last_modified: datetime
    expiry: Optional[datetime]
    storage_class: StorageClass
    encryption: Optional[ServerSideEncryption]
    kms_key_id: Optional[SSEKMSKeyId]
    bucket_key_enabled: Optional[bool]
    checksum_algorithm: ChecksumAlgorithm
    checksum_value: str
    lock_mode: Optional[ObjectLockMode]
    lock_legal_status: Optional[ObjectLockLegalHoldStatus]
    lock_until: Optional[datetime]
    acl: Optional[str]  # TODO: we need to change something here, how it's done?


class S3DeleteMarker:
    key: str
    version_id: str
    last_modified: datetime
    pass


class S3Multipart:
    pass


class S3Part:
    pass


class _VersionedKeyStore(dict):  # type: ignore

    """A modified version of Moto's `_VersionedKeyStore`"""

    def __sgetitem__(self, key: str) -> list[S3Object | S3DeleteMarker]:
        return super().__getitem__(key)

    # def pop(self, key: str) -> None:
    # for version in self.getlist(key, []):
    #     version.dispose()
    # super().pop(key)

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

    def override_last_version(self, key: str, value: S3Object | S3DeleteMarker) -> None:
        try:
            self.__sgetitem__(key)[-1] = value
        except (KeyError, IndexError):
            super().__setitem__(key, [value])

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

        size = sum(key.size for key in self.values())
        return size
        # size = 0
        # for val in self._self_iterable().values():
        #     # TODO: not sure about that, especially storage values from tempfile?
        #     # Should we iterate on key.size instead? and on every version? because we don't store diff or anything?
        #     # not sure
        #     size += val.size
        #     # size += sys.getsizeof(val)
        # return size

    def _self_iterable(self) -> dict[str, S3Object | S3DeleteMarker]:
        # TODO: locking
        #  to enable concurrency, return a copy, to avoid "dictionary changed size during iteration"
        #  TODO: look into replacing with a locking mechanism, potentially
        return dict(self)

    items = iteritems = _iteritems  # type: ignore
    lists = iterlists = _iterlists
    values = itervalues = _itervalues  # type: ignore


class S3StoreV2(BaseStore):
    buckets: dict[BucketName, S3Bucket] = CrossRegionAttribute(default=dict)


class BucketCorsIndexV2:
    def __init__(self):
        self._cors_index_cache = None
        self._bucket_index_cache = None

    @property
    def cors(self) -> dict[str, CORSConfiguration]:
        if self._cors_index_cache is None:
            self._cors_index_cache = self._build_index()
        return self._cors_index_cache

    @property
    def buckets(self) -> set[str]:
        if self._bucket_index_cache is None:
            self._bucket_index_cache = self._build_index()
        return self._bucket_index_cache

    def invalidate(self):
        self._cors_index_cache = None
        self._bucket_index_cache = None

    @staticmethod
    def _build_index() -> tuple[set[BucketName], dict[BucketName, CORSConfiguration]]:
        buckets = set()
        cors_index = {}
        for account_id, regions in s3_stores_v2.items():
            for bucket_name, bucket in regions[config.DEFAULT_REGION].buckets.items():
                bucket: S3Bucket
                buckets.add(bucket_name)
                if bucket.cors_rules is not None:
                    cors_index[bucket_name] = bucket.cors_rules

        return buckets, cors_index


s3_stores_v2 = AccountRegionBundle[S3StoreV2]("s3", S3StoreV2)
