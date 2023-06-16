# TODO, for now, this file will contain only files for the new S3 provider but not compatible with persistence
# it will then put in the other models file?
# do something specific in the persistence file?
import base64
import hashlib
import logging
import threading
from collections import defaultdict
from datetime import datetime
from io import RawIOBase
from tempfile import SpooledTemporaryFile
from typing import IO, Iterator, Literal, Optional

from werkzeug.datastructures.headers import Headers

from localstack import config
from localstack.aws.api.s3 import (  # BucketCannedACL,; ServerSideEncryptionRules,
    AccountId,
    AnalyticsConfiguration,
    AnalyticsId,
    Body,
    BucketAccelerateStatus,
    BucketName,
    BucketRegion,
    ChecksumAlgorithm,
    CompletedPartList,
    CORSConfiguration,
    ETag,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    LifecycleRules,
    LoggingEnabled,
    Metadata,
    MethodNotAllowed,
    MultipartUploadId,
    NoSuchKey,
    NoSuchVersion,
    NotificationConfiguration,
    ObjectKey,
    ObjectLockConfiguration,
    ObjectLockLegalHoldStatus,
    ObjectLockMode,
    ObjectOwnership,
    ObjectVersionId,
    Owner,
    PartNumber,
    Payer,
    Policy,
    PublicAccessBlockConfiguration,
    ReplicationConfiguration,
    ServerSideEncryption,
    ServerSideEncryptionRule,
    Size,
    SSEKMSKeyId,
    StorageClass,
    WebsiteConfiguration,
    WebsiteRedirectLocation,
)
from localstack.services.s3.constants import S3_CHUNK_SIZE, S3_UPLOAD_PART_MIN_SIZE
from localstack.services.s3.exceptions import InvalidRequest
from localstack.services.s3.utils import ParsedRange, get_owner_for_account_id, get_s3_checksum
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
LOG = logging.getLogger(__name__)

KEY_STORAGE_CLASS = SpooledTemporaryFile


def create_key_storage():
    # we can pass extra arguments here and all?
    # let's see how to make it configurable
    return KEY_STORAGE_CLASS(max_size=16)


# TODO move to utils?
def iso_8601_datetime_without_milliseconds_s3(
    value: datetime,
) -> Optional[str]:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z") if value else None


RFC1123 = "%a, %d %b %Y %H:%M:%S GMT"


def rfc_1123_datetime(src: datetime) -> str:
    return src.strftime(RFC1123)


def str_to_rfc_1123_datetime(value: str) -> datetime:
    return datetime.strptime(value, RFC1123)


# TODO: we will need a versioned key store as well, let's check what we can get better
class S3Bucket:
    name: BucketName
    bucket_account_id: AccountId
    bucket_region: BucketRegion
    creation_date: datetime
    multiparts: dict[MultipartUploadId, "S3Multipart"]  # TODO: is there a key thing here?
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
    encryption_rule: Optional[
        ServerSideEncryptionRule
    ]  # TODO validate if there can be more than one rule
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
        self.encryption_rule = None  # TODO
        self.creation_date = datetime.now()
        self.multiparts = {}
        # we set the versioning status to None instead of False to be able to differentiate between a bucket which
        # was enabled at some point and one fresh bucket
        self.versioning_status = None
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_Owner.html
        self.owner = get_owner_for_account_id(account_id)

    def get_object(
        self,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        http_method: Literal["GET", "PUT", "HEAD"] = "GET",  # TODO: better?
    ) -> "S3Object":
        """
        :param key: the Object Key
        :param version_id: optional, the versionId of the object
        :param http_method: the HTTP method of the original call. This is necessary for the exception if the bucket is
        versioned or suspended
        see: https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html
        :return:
        :raises NoSuchKey if the object key does not exist at all, or if the object is a DeleteMarker
        :raises MethodNotAllowed if the object is a DeleteMarker and the operation is not allowed against it
        """
        if version_id:
            s3_object_version = self.objects.get_version(key, version_id)
            if not s3_object_version:
                raise NoSuchVersion(
                    "The specified version does not exist.",
                    Key=key,
                    VersionId=version_id,
                )
            elif isinstance(s3_object_version, S3DeleteMarker):
                raise MethodNotAllowed(
                    "The specified method is not allowed against this resource.",
                    Method=http_method,
                    ResourceType="DeleteMarker",
                    DeleteMarker=True,
                    Allow="delete",
                )
            return s3_object_version

        s3_object = self.objects.get(key)

        if not s3_object:
            raise NoSuchKey("The specified key does not exist.", Key=key)

        elif isinstance(s3_object, S3DeleteMarker):
            raise NoSuchKey(
                "The specified key does not exist.",
                Key=key,
                DeleteMarker=True,
            )

        return s3_object


class S3Object:
    value: KEY_STORAGE_CLASS  # TODO: locking / make it configurable to be able to just use filestream
    key: ObjectKey
    version_id: Optional[ObjectVersionId]
    size: Size
    etag: ETag
    metadata: Metadata  # TODO: check this?
    last_modified: datetime
    expiry: Optional[datetime]
    expires: Optional[datetime]
    expiration: Optional[datetime]
    storage_class: StorageClass
    encryption: Optional[ServerSideEncryption]
    kms_key_id: Optional[SSEKMSKeyId]
    bucket_key_enabled: Optional[bool]
    checksum_algorithm: ChecksumAlgorithm
    checksum_value: str
    lock_mode: Optional[ObjectLockMode]
    lock_legal_status: Optional[ObjectLockLegalHoldStatus]
    lock_until: Optional[datetime]
    website_redirect_location: Optional[WebsiteRedirectLocation]
    acl: Optional[str]  # TODO: we need to change something here, how it's done?
    is_current: bool
    parts: Optional[list[tuple[str, str]]]

    def __init__(
        self,
        key: ObjectKey,
        value: Optional[IO[bytes]],
        metadata: Optional[Metadata] = None,
        storage_class: StorageClass = StorageClass.STANDARD,
        expires: Optional[datetime] = None,
        expiration: Optional[datetime] = None,  # come from lifecycle
        checksum_algorithm: Optional[ChecksumAlgorithm] = None,
        checksum_value: Optional[str] = None,
        encryption: Optional[ServerSideEncryption] = None,  # inherit bucket
        kms_key_id: Optional[SSEKMSKeyId] = None,  # inherit bucket
        bucket_key_enabled: bool = False,  # inherit bucket
        lock_mode: Optional[ObjectLockMode] = None,  # inherit bucket
        lock_legal_status: Optional[ObjectLockLegalHoldStatus] = None,  # inherit bucket
        lock_until: Optional[datetime] = None,
        website_redirect_location: Optional[WebsiteRedirectLocation] = None,
        acl: Optional[str] = None,  # TODO
        expiry: Optional[datetime] = None,  # TODO
        decoded_content_length: Optional[int] = None,  # TODO: this is for `aws-chunk` requests
        # etag: Optional[ETag] = None,  # TODO: this for multipart op
        # parts: Optional[list[tuple[str, str]]] = None,  # TODO: maybe remove?
    ):
        self.lock = threading.RLock()
        self.key = key
        self.metadata = metadata
        self.version_id = None
        self.storage_class = storage_class
        self.expires = expires
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
        self.expiry = expiry
        self.expiration = expiration
        self.website_redirect_location = website_redirect_location
        self.is_current = True
        self.value = create_key_storage()
        self.last_modified = datetime.now()
        self.size = 0
        # self.parts = parts

        # TODO: clean up?
        if value is not None:

            # if isinstance(value, KEY_STORAGE_CLASS):
            #     self._set_value_from_multipart(value, etag)
            if decoded_content_length is not None:
                self._set_value_from_chunked_stream(value, decoded_content_length)
            else:
                self._set_value_from_stream(value)

    # TODO: remove this, we will manipulate the object directly from the multipart?
    def _set_value_from_multipart(self, value: KEY_STORAGE_CLASS, etag: ETag):
        self.value = value
        self.etag = etag

    def _set_value_from_stream(self, value: IO[bytes]):
        with self.lock:
            self.value.seek(0)
            self.value.truncate()
            # We have 2 cases:
            # The client gave a checksum value, we will need to compute the value and validate it against
            # or the client have an algorithm value only and we need to compute the checksum
            checksum = None
            calculated_checksum = None
            if self.checksum_algorithm:
                checksum = get_s3_checksum(self.checksum_algorithm)

            etag = hashlib.md5(usedforsecurity=False)

            while data := value.read(S3_CHUNK_SIZE):
                self.value.write(data)
                etag.update(data)
                if self.checksum_algorithm:
                    checksum.update(data)

            if self.checksum_algorithm:
                calculated_checksum = base64.b64encode(checksum.digest()).decode()

            if self.checksum_value and self.checksum_value != calculated_checksum:
                raise InvalidRequest(
                    f"Value for x-amz-checksum-{self.checksum_algorithm.lower()} header is invalid."
                )

            self.etag = etag.hexdigest()

            self.size = self.value.tell()
            self.value.seek(0)

    def _set_value_from_chunked_stream(self, value: IO[bytes], decoded_length: int):
        with self.lock:
            self.value.seek(0)
            self.value.truncate()
            # We have 2 cases:
            # The client gave a checksum value, we will need to compute the value and validate it against
            # or the client have an algorithm value only and we need to compute the checksum
            checksum = None
            calculated_checksum = None
            if self.checksum_algorithm:
                checksum = get_s3_checksum(self.checksum_algorithm)
            etag = hashlib.md5(usedforsecurity=False)

            written = 0
            while written < decoded_length:
                line = value.readline()
                chunk_length = int(line.split(b";")[0], 16)

                while chunk_length > 0:
                    amount = min(chunk_length, S3_CHUNK_SIZE)
                    data = value.read(amount)
                    self.value.write(data)

                    real_amount = len(data)
                    chunk_length -= real_amount
                    written += real_amount

                    etag.update(data)
                    if self.checksum_algorithm:
                        checksum.update(data)

                # remove trailing \r\n
                value.read(2)

            trailing_headers = []
            next_line = value.readline()

            if next_line:
                try:
                    chunk_length = int(next_line.split(b";")[0], 16)
                    if chunk_length != 0:
                        LOG.warning("The S3 object body didn't conform to the aws-chunk format")
                except ValueError:
                    trailing_headers.append(next_line.strip())

                # try for trailing headers after
                while line := value.readline():
                    trailing_header = line.strip()
                    if trailing_header:
                        trailing_headers.append(trailing_header)

            # look for the checksum header in the trailing headers
            # TODO: we could get the header key from x-amz-trailer as well
            for trailing_header in trailing_headers:
                try:
                    header_key, header_value = trailing_header.decode("utf-8").split(
                        ":", maxsplit=1
                    )
                    if header_key.lower() == f"x-amz-checksum-{self.checksum_algorithm}".lower():
                        self.checksum_value = header_value
                except (IndexError, ValueError, AttributeError):
                    continue

            if self.checksum_algorithm:
                calculated_checksum = base64.b64encode(checksum.digest()).decode()

            if self.checksum_value and self.checksum_value != calculated_checksum:
                raise InvalidRequest(
                    f"Value for x-amz-checksum-{self.checksum_algorithm.lower()} header is invalid."
                )

            self.etag = etag.hexdigest()
            self.size = self.value.tell()
            self.value.seek(0)

    def get_metadata_headers(self):
        headers = Headers()
        headers["LastModified"] = self.last_modified_rfc1123
        headers["ContentLength"] = str(self.size)
        headers["ETag"] = f'"{self.etag}"'
        if self.expires:
            headers["Expires"] = self.expires_rfc1123

        for metadata_key, metadata_value in self.metadata.items():
            headers[metadata_key] = metadata_value

        return headers

    @property
    def last_modified_iso8601(self) -> str:
        return iso_8601_datetime_without_milliseconds_s3(self.last_modified)  # type: ignore

    @property
    def last_modified_rfc1123(self) -> str:
        # Different datetime formats depending on how the key is obtained
        # https://github.com/boto/boto/issues/466
        return rfc_1123_datetime(self.last_modified)

    @property
    def expires_rfc1123(self) -> str:
        return rfc_1123_datetime(self.expires)

    @property
    def etag_header(self) -> str:
        return f'"{self.etag}"'

    # TODO: these are for returning the data to Werkzeug, allow for more control over how we return the data
    def get_body_iterator(self) -> Iterator[Body]:
        def get_stream_iterator() -> bytes:
            pos = 0
            while True:
                self.value.seek(pos)  # TODO: is seek an heavy op?
                data = self.value.read(S3_CHUNK_SIZE)
                if not data:
                    return b""

                read = len(data)
                pos += read

                yield data

        return get_stream_iterator()

    # TODO: these are for returning the data to Werkzeug, allow for more control over how we return the data
    def get_range_body_iterator(self, range_data: ParsedRange) -> Iterator[Body]:
        def get_range_stream_iterator() -> bytes:
            pos = range_data.begin
            max_length = range_data.content_length
            while True:
                self.value.seek(pos)  # TODO: is seek an heavy op?
                # don't read more than the max content-length
                amount = min(max_length, S3_CHUNK_SIZE)
                data = self.value.read(amount)
                if not data:
                    return b""

                read = len(data)
                pos += read
                max_length -= read

                yield data

        return get_range_stream_iterator()


class S3DeleteMarker:
    key: ObjectKey
    version_id: str
    last_modified: datetime

    def __init__(self, key: ObjectKey):
        self.key = key
        self.version_id = "randomkk"  # TODO
        self.last_modified = datetime.now()


class S3Part:
    part_number: PartNumber
    etag: ETag
    value: KEY_STORAGE_CLASS
    last_modified: datetime
    checksum_algorithm: Optional[ChecksumAlgorithm]
    checksum_value: Optional[str]
    lock: threading.RLock

    def __init__(
        self,
        part_number: PartNumber,
        value: Optional[IO[bytes] | "PartialStream"],
        checksum_algorithm: Optional[ChecksumAlgorithm] = None,
        checksum_value: Optional[str] = None,
        decoded_content_length: Optional[int] = None,
    ):
        self.lock = threading.RLock()
        self.last_modified = datetime.now()
        self.part_number = part_number
        self.checksum_algorithm = checksum_algorithm
        self.checksum_value = checksum_value
        self.value = create_key_storage()
        if decoded_content_length:
            self._set_value_from_chunked_stream(value, decoded_content_length)
        else:
            self._set_value_from_stream(value)

    @property
    def etag_header(self) -> str:
        return f'"{self.etag}"'

    def _set_value_from_stream(self, value: IO[bytes] | "PartialStream"):
        with self.lock:
            self.value.seek(0)
            self.value.truncate()
            # We have 2 cases:
            # The client gave a checksum value, we will need to compute the value and validate it against
            # or the client have an algorithm value only and we need to compute the checksum
            checksum = None
            calculated_checksum = None
            if self.checksum_algorithm:
                checksum = get_s3_checksum(self.checksum_algorithm)

            etag = hashlib.md5(usedforsecurity=False)

            while data := value.read(S3_CHUNK_SIZE):
                self.value.write(data)
                etag.update(data)
                if self.checksum_algorithm:
                    checksum.update(data)

            if self.checksum_algorithm:
                calculated_checksum = base64.b64encode(checksum.digest()).decode()

            # TODO: mandatory checksum value provided? same for get object
            # only copy object wont need it
            if self.checksum_value and self.checksum_value != calculated_checksum:
                raise InvalidRequest(
                    f"Value for x-amz-checksum-{self.checksum_algorithm.lower()} header is invalid."
                )

            self.etag = etag.hexdigest()

            self.size = self.value.tell()
            self.value.seek(0)

    def _set_value_from_chunked_stream(self, value: IO[bytes], decoded_length: int):
        with self.lock:
            self.value.seek(0)
            self.value.truncate()
            # We have 2 cases:
            # The client gave a checksum value, we will need to compute the value and validate it against
            # or the client have an algorithm value only and we need to compute the checksum
            checksum = None
            calculated_checksum = None
            if self.checksum_algorithm:
                checksum = get_s3_checksum(self.checksum_algorithm)
            etag = hashlib.md5(usedforsecurity=False)

            written = 0
            while written < decoded_length:
                line = value.readline()
                chunk_length = int(line.split(b";")[0], 16)

                while chunk_length > 0:
                    amount = min(chunk_length, S3_CHUNK_SIZE)
                    data = value.read(amount)
                    self.value.write(data)

                    real_amount = len(data)
                    chunk_length -= real_amount
                    written += real_amount

                    etag.update(data)
                    if self.checksum_algorithm:
                        checksum.update(data)

                # remove trailing \r\n
                value.read(2)

            trailing_headers = []
            next_line = value.readline()

            if next_line:
                try:
                    chunk_length = int(next_line.split(b";")[0], 16)
                    if chunk_length != 0:
                        LOG.warning("The S3 object body didn't conform to the aws-chunk format")
                except ValueError:
                    trailing_headers.append(next_line.strip())

                # try for trailing headers after
                while line := value.readline():
                    trailing_header = line.strip()
                    if trailing_header:
                        trailing_headers.append(trailing_header)

            # look for the checksum header in the trailing headers
            # TODO: we could get the header key from x-amz-trailer as well
            for trailing_header in trailing_headers:
                try:
                    header_key, header_value = trailing_header.decode("utf-8").split(
                        ":", maxsplit=1
                    )
                    if header_key.lower() == f"x-amz-checksum-{self.checksum_algorithm}".lower():
                        self.checksum_value = header_value
                except (IndexError, ValueError, AttributeError):
                    continue

            if self.checksum_algorithm:
                calculated_checksum = base64.b64encode(checksum.digest()).decode()

            if self.checksum_value and self.checksum_value != calculated_checksum:
                raise InvalidRequest(
                    f"Value for x-amz-checksum-{self.checksum_algorithm.lower()} header is invalid."
                )

            self.etag = etag.hexdigest()
            self.size = self.value.tell()
            self.value.seek(0)


class S3Multipart:
    parts: dict[PartNumber, S3Part]
    object: S3Object
    upload_id: MultipartUploadId
    checksum_value: Optional[str]

    def __init__(
        self,
        key: ObjectKey,
        metadata: Optional[Metadata] = None,
        storage_class: StorageClass = StorageClass.STANDARD,
        expires: Optional[datetime] = None,
        expiration: Optional[datetime] = None,  # come from lifecycle
        checksum_algorithm: Optional[ChecksumAlgorithm] = None,
        encryption: Optional[ServerSideEncryption] = None,  # inherit bucket
        kms_key_id: Optional[SSEKMSKeyId] = None,  # inherit bucket
        bucket_key_enabled: bool = False,  # inherit bucket
        lock_mode: Optional[ObjectLockMode] = None,  # inherit bucket
        lock_legal_status: Optional[ObjectLockLegalHoldStatus] = None,  # inherit bucket
        lock_until: Optional[datetime] = None,
        website_redirect_location: Optional[WebsiteRedirectLocation] = None,
        acl: Optional[str] = None,  # TODO
        expiry: Optional[datetime] = None,  # TODO
    ):
        self.id = "randommultipart"  # TODO
        self.parts = {}
        self.object = S3Object(
            key=key,
            value=None,
            metadata=metadata,
            storage_class=storage_class,
            expires=expires,
            expiration=expiration,
            checksum_algorithm=checksum_algorithm,
            encryption=encryption,
            kms_key_id=kms_key_id,
            bucket_key_enabled=bucket_key_enabled,
            lock_mode=lock_mode,
            lock_legal_status=lock_legal_status,
            lock_until=lock_until,
            website_redirect_location=website_redirect_location,
            acl=acl,
            expiry=expiry,
        )
        self.checksum_value = None

    def complete_multipart(self, parts: CompletedPartList):
        last_part_index = len(parts) - 1
        checksum_key = f"Checksum{self.object.checksum_algorithm.upper()}"
        object_stream = self.object.value
        object_etag = hashlib.md5(usedforsecurity=False)
        for index, part in enumerate(parts):
            part_number = part["PartNumber"]
            part_etag = part["ETag"]
            # TODO: verify checksum part, maybe from the algo?
            part_checksum = part.get(checksum_key)

            s3_part = self.parts.get(part_number)
            # TODO: verify etag format here
            if not s3_part or s3_part.etag != part_etag.strip('"'):
                object_stream.seek(0)
                object_stream.truncate()
                # raise InvalidPart()
                raise
            # TODO: validate this?
            if part_checksum and part_checksum != s3_part.checksum_value:
                object_stream.seek(0)
                object_stream.truncate()
                # raise InvalidPart()
                raise
            if index != last_part_index and s3_part.size < S3_UPLOAD_PART_MIN_SIZE:
                object_stream.seek(0)
                object_stream.truncate()
                # raise EntityTooSmall()
                raise

            stream_value = s3_part.value
            while data := stream_value.read(S3_CHUNK_SIZE):
                object_stream.write(data)

            object_etag.update(bytes.fromhex(s3_part.etag))

        multipart_etag = f"{object_etag.hexdigest()}-{len(parts)}"
        self.object.etag = multipart_etag

        # free the space before the garbage collection, just to be faster
        for part in self.parts.values():
            part.value.close()

        # now the full data should be in self.object.value, and the etag set
        # we can now properly retrieve the S3Object from the S3Multipart, set it as its own key
        # and delete the multipart
        # TODO: set the parts list to support `PartNumber` in GetObject !!


class _VersionedKeyStore(dict):  # type: ignore

    """A modified version of Moto's `_VersionedKeyStore`"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stored_versions = defaultdict(set)
        self._lock = threading.RLock()

    def get_versions_for_key(self, key: str) -> set[str]:
        return self._stored_versions.get(key)

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
        if value.version_id:
            self._stored_versions[key].add(value.version_id)

    def pop(
        self, key: str, default: S3Object | S3DeleteMarker = None
    ) -> list[S3Object | S3DeleteMarker]:
        value = super().pop(key, None)
        if not value:
            return [default]
        self._stored_versions.pop(key, None)
        return value

    def get(self, key: str, default: S3Object | S3DeleteMarker = None) -> S3Object | S3DeleteMarker:
        """
        :param key: the ObjectKey
        :param default: default return value if the key is not present
        :return: the current (last version) S3Object or DeleteMarker
        """
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

    # TODO: could it actually append one version on top instead? hmm
    def set_last_version(self, key: str, value: S3Object | S3DeleteMarker) -> None:
        try:
            self.__sgetitem__(key)[-1] = value
        except (KeyError, IndexError):
            super().__setitem__(key, [value])

    def get_version(
        self, key: str, version_id: str, default: S3Object | S3DeleteMarker = None
    ) -> Optional[S3Object | S3DeleteMarker]:
        s3_object_versions = self.getlist(key=key, default=default)
        if not s3_object_versions:
            return default

        for s3_object_version in s3_object_versions:
            if s3_object_version.version_id == version_id:
                return s3_object_version

        return None

    def getlist(
        self, key: str, default: list[S3Object | S3DeleteMarker] = None
    ) -> list[S3Object | S3DeleteMarker]:
        try:
            return self.__sgetitem__(key)
        except (KeyError, IndexError):
            pass
        return default

    def setlist(self, key: str, _list: list[S3Object | S3DeleteMarker]) -> None:
        for value in _list:
            if value.version_id:
                self._stored_versions[key].add(value.version_id)

        if _list:
            super().__setitem__(key, _list)
        else:
            self.pop(key)

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

    items = iteritems = _iteritems
    lists = iterlists = _iterlists
    values = itervalues = _itervalues


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


class PartialStream(RawIOBase):
    def __init__(self, base_stream: IO[bytes], range_data: ParsedRange):
        super().__init__()
        self._base_stream = base_stream
        self._pos = range_data.begin
        self._max_length = range_data.content_length

    def read(self, s: int = -1) -> bytes | None:
        self._base_stream.seek(self._pos)

        if s is None or s < 0:
            amount = self._max_length
        else:
            amount = min(self._max_length, s)

        data = self._base_stream.read(amount)
        if not data:
            return b""
        read_amount = len(data)
        self._max_length -= read_amount
        self._pos += read_amount

        return data

    def readable(self) -> bool:
        return True


s3_stores_v2 = AccountRegionBundle[S3StoreV2]("s3", S3StoreV2)
