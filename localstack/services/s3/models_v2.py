# TODO, for now, this file will contain only files for the new S3 provider but not compatible with persistence
# it will then put in the other models file?
# do something specific in the persistence file?
from datetime import datetime
from tempfile import SpooledTemporaryFile
from typing import IO, Iterator, Optional

from localstack import config
from localstack.aws.api.s3 import (  # BucketCannedACL,
    AccountId,
    AnalyticsConfiguration,
    AnalyticsId,
    BucketAccelerateStatus,
    BucketName,
    BucketRegion,
    ChecksumAlgorithm,
    CORSConfiguration,
    ETag,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    LifecycleRules,
    LoggingEnabled,
    Metadata,
    NotificationConfiguration,
    ObjectKey,
    ObjectLockConfiguration,
    ObjectLockLegalHoldStatus,
    ObjectLockMode,
    ObjectOwnership,
    ObjectVersionId,
    Owner,
    Payer,
    Policy,
    PublicAccessBlockConfiguration,
    ReplicationConfiguration,
    ServerSideEncryption,
    ServerSideEncryptionRules,
    Size,
    SSEKMSKeyId,
    StorageClass,
    WebsiteConfiguration,
)
from localstack.services.s3.utils import get_owner_for_account_id
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    CrossRegionAttribute,
)

# TODO: beware of timestamp data, we need the snapshot to be more precise for S3, with the different types
# moto had a lot of issue with it? not sure about our parser/serializer

# for persistence, append the version id to the key name using a special symbol?? like __version_id__={version_id}

# TODO: we need to make the SpooledTemporaryFile configurable for persistence?

KEY_STORAGE_CLASS = SpooledTemporaryFile


def create_key_storage():
    # we can pass extra arguments here and all?
    # let's see how to make it configurable
    return KEY_STORAGE_CLASS(max_size=16)


# TODO: we will need a versioned key store as well, let's check what we can get better
class S3Bucket:
    name: BucketName
    bucket_account_id: AccountId
    bucket_region: BucketRegion
    creation_date: datetime
    multiparts: dict
    objects: "_VersionedKeyStore"
    versioning_status: Optional[bool]
    lifecycle_rules: LifecycleRules
    policy: Optional[Policy]
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
    owner: Owner

    # set all buckets parameters here
    # first one in moto, then one in our provider added (cors, lifecycle and such)
    def __init__(
        self,
        name: BucketName,
        account_id: AccountId,
        bucket_region: BucketRegion,
        acl=None,  # TODO: validate ACL first, create utils for validating and consolidating
        object_ownership: ObjectOwnership = None,
        object_lock_enabled_for_bucket: bool = None,
    ):
        self.name = name
        self.bucket_account_id = account_id
        self.bucket_region = bucket_region
        self.objects = _VersionedKeyStore()
        # self.acl
        self.object_ownership = object_ownership
        self.object_lock_enabled = object_lock_enabled_for_bucket
        self.creation_date = datetime.now()
        self.multiparts = {}
        # we set the versioning status to None instead of False to be able to differentiate between a bucket which
        # was enabled at some point and one fresh bucket
        self.versioning_status = None
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_Owner.html
        self.owner = get_owner_for_account_id(account_id)


class S3Object:
    value: KEY_STORAGE_CLASS  # TODO: locking / make it configurable to be able to just use filestream
    key: ObjectKey
    version_id: Optional[ObjectVersionId]
    size: Size
    etag: ETag
    metadata: Metadata  # TODO: check this?
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
    is_current: bool

    def __init__(
        self,
        key: ObjectKey,
        value: Optional[IO[bytes]],
        metadata: Metadata,
        storage_class: StorageClass = StorageClass.STANDARD,
        checksum_algorithm: Optional[ChecksumAlgorithm] = None,
        checksum_value: Optional[str] = None,
        encryption: Optional[ServerSideEncryption] = None,  # inherit bucket
        kms_key_id: Optional[SSEKMSKeyId] = None,  # inherit bucket
        bucket_key_enabled: bool = False,  # inherit bucket
        lock_mode: Optional[ObjectLockMode] = None,  # inherit bucket
        lock_legal_status: Optional[ObjectLockLegalHoldStatus] = None,  # inherit bucket
        lock_until: Optional[datetime] = None,
        acl: Optional[str] = None,  # TODO
    ):
        self.key = key
        self.metadata = metadata
        self.storage_class = storage_class
        self.checksum_algorithm = checksum_algorithm
        self.checksum_value = checksum_value
        self.encryption = encryption
        # TODO: validate the format, always store the ARN even if just the ID
        self.kms_key_id = kms_key_id
        self.bucket_key_enabled = bucket_key_enabled
        self.lock_mode = lock_mode
        self.lock_legal_status = lock_legal_status
        self.lock_until = lock_until
        self.acl = acl
        self.is_current = True

        self.value = create_key_storage()

        self._set_value(value)

    def _set_value(self, value: IO[bytes]):
        pass


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

    def set_last_version(self, key: str, value: S3Object | S3DeleteMarker) -> None:
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
    global_bucket_map: dict[BucketName, AccountId] = CrossAccountAttribute(default=dict)


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
