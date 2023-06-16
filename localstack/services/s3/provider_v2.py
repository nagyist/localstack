# from typing import Optional
import contextlib

from localstack import config

# from localstack.aws.api import CommonServiceException, RequestContext, ServiceException, handler
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.s3 import (  # BucketName, CreateBucketConfiguration,; InvalidBucketName,; DeleteObjectRequest,; DeleteObjectsRequest,
    MFA,
    AccountId,
    Bucket,
    BucketAlreadyExists,
    BucketAlreadyOwnedByYou,
    BucketName,
    BypassGovernanceRetention,
    ChecksumAlgorithm,
    CopyObjectOutput,
    CopyObjectRequest,
    CopyObjectResult,
    CopyPartResult,
    CreateBucketOutput,
    CreateBucketRequest,
    CreateMultipartUploadOutput,
    CreateMultipartUploadRequest,
    Delete,
    DeleteObjectOutput,
    DeleteObjectsOutput,
    GetObjectAttributesOutput,
    GetObjectAttributesParts,
    GetObjectAttributesRequest,
    GetObjectOutput,
    GetObjectRequest,
    HeadBucketOutput,
    HeadObjectOutput,
    HeadObjectRequest,
    InvalidArgument,
    InvalidStorageClass,
    ListBucketsOutput,
    NoSuchBucket,
    NoSuchUpload,
    ObjectKey,
    ObjectVersionId,
    PutObjectOutput,
    PutObjectRequest,
    RequestPayer,
    S3Api,
    ServerSideEncryption,
    StorageClass,
    UploadPartCopyOutput,
    UploadPartCopyRequest,
    UploadPartOutput,
    UploadPartRequest,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.constants import ARCHIVES_STORAGE_CLASSES
from localstack.services.s3.exceptions import (
    BucketNotEmpty,
    InvalidLocationConstraint,
    InvalidRequest,
    MalformedXML,
)
from localstack.services.s3.models_v2 import (
    PartialStream,
    S3Bucket,
    S3DeleteMarker,
    S3Multipart,
    S3Object,
    S3Part,
    S3StoreV2,
    s3_stores_v2,
)
from localstack.services.s3.utils import (
    extract_bucket_key_version_id_from_copy_source,
    get_class_attrs_from_spec_class,
    get_full_default_bucket_location,
    get_metadata_from_headers,
    get_owner_for_account_id,
    parse_range_header,
    validate_kms_key_id,
)

STORAGE_CLASSES = get_class_attrs_from_spec_class(StorageClass)

# TODO: pre-signed URLS -> REMAP parameters from querystring to headers???


class S3Provider(S3Api, ServiceLifecycleHook):
    @staticmethod
    def get_store(account_id: str, region_name: str) -> S3StoreV2:
        # if not context:
        #     return s3_stores_v2[get_aws_account_id()][aws_stack.get_region()]
        # Use default account id for external access? would need an anonymous one?

        return s3_stores_v2[account_id][region_name]

    @handler("CreateBucket", expand=False)
    def create_bucket(
        self,
        context: RequestContext,
        request: CreateBucketRequest,
        # bucket: BucketName,
        # acl: BucketCannedACL = None,
        # create_bucket_configuration: CreateBucketConfiguration = None,
        # grant_full_control: GrantFullControl = None,
        # grant_read: GrantRead = None,
        # grant_read_acp: GrantReadACP = None,
        # grant_write: GrantWrite = None,
        # grant_write_acp: GrantWriteACP = None,
        # object_lock_enabled_for_bucket: ObjectLockEnabledForBucket = None,
        # object_ownership: ObjectOwnership = None,
    ) -> CreateBucketOutput:
        # Do we set default encryption like AWS? YES
        # Do we block setting ACLs like AWS? uhhh good question? let's see after?
        bucket_name = request["Bucket"]
        # TODO: 3 and 63
        # if not MIN_BUCKET_NAME_LENGTH <= len(bucket_name) <= MAX_BUCKET_NAME_LENGTH:
        #     raise InvalidBucketName()
        if create_bucket_configuration := request.get("CreateBucketConfiguration"):
            if not (bucket_region := create_bucket_configuration.get("LocationConstraint")):
                raise MalformedXML()

            if bucket_region == "us-east-1":
                raise InvalidLocationConstraint("The specified location-constraint is not valid")
        else:
            bucket_region = "us-east-1"

        store = self.get_store(context.account_id, bucket_region)

        if bucket_name in store.global_bucket_map:
            existing_bucket_owner = store.global_bucket_map[bucket_name]
            if existing_bucket_owner != context.account_id:
                raise BucketAlreadyExists()

            # if the existing bucket has the same owner, the behaviour will depend on the region
            if bucket_region != "us-east-1":
                raise BucketAlreadyOwnedByYou()

        s3_bucket = S3Bucket(
            name=bucket_name,
            account_id=context.account_id,
            bucket_region=bucket_region,
            acl=None,  # TODO: validate ACL first, create utils for validating and consolidating
            object_ownership=request.get("ObjectOwnership"),
            object_lock_enabled_for_bucket=request.get("ObjectLockEnabledForBucket"),
        )
        store.buckets[bucket_name] = s3_bucket

        # Location is always contained in response -> full url for LocationConstraint outside us-east-1
        location = (
            f"/{bucket_name}"
            if bucket_region == "us-east-1"
            else get_full_default_bucket_location(bucket_name)
        )
        response = CreateBucketOutput(Location=location)
        return response

    def delete_bucket(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> None:
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        # the bucket still contains objects
        if s3_bucket.objects:
            # TODO: try with a key containing only DeleteMarker?

            # TODO: aws validate once we implemented objects
            raise BucketNotEmpty(
                message="The bucket you tried to delete is not empty",
                BucketName=bucket,
            )

        store.buckets.pop(bucket)

    def list_buckets(
        self,
        context: RequestContext,
    ) -> ListBucketsOutput:
        owner = get_owner_for_account_id(context.account_id)
        store = self.get_store(context.account_id, context.region)
        buckets = []
        for bucket in store.buckets.values():
            buckets.append(
                Bucket(
                    Name=bucket.name,
                    CreationDate=bucket.creation_date,
                )
            )
        return ListBucketsOutput(Owner=owner, Buckets=buckets)

    def head_bucket(
        self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    ) -> HeadBucketOutput:
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            # just to return the 404 error message
            raise NoSuchBucket()

        # TODO: this call is also used to check if the user has access/authorization for the bucket, it can return 403
        return HeadBucketOutput(BucketRegion=s3_bucket.bucket_region)

    # def get_bucket_location(
    #     self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    # ) -> GetBucketLocationOutput:
    #     pass

    @handler("PutObject", expand=False)
    def put_object(
        self,
        context: RequestContext,
        request: PutObjectRequest,
        # bucket: BucketName,
        # key: ObjectKey,
        # acl: ObjectCannedACL = None,
        # body: IO[Body] = None,
        # cache_control: CacheControl = None,
        # content_disposition: ContentDisposition = None,
        # content_encoding: ContentEncoding = None,
        # content_language: ContentLanguage = None,
        # content_length: ContentLength = None,
        # content_md5: ContentMD5 = None,
        # content_type: ContentType = None,
        # checksum_algorithm: ChecksumAlgorithm = None,
        # checksum_crc32: ChecksumCRC32 = None,
        # checksum_crc32_c: ChecksumCRC32C = None,
        # checksum_sha1: ChecksumSHA1 = None,
        # checksum_sha256: ChecksumSHA256 = None,
        # expires: Expires = None,
        # grant_full_control: GrantFullControl = None,
        # grant_read: GrantRead = None,
        # grant_read_acp: GrantReadACP = None,
        # grant_write_acp: GrantWriteACP = None,
        # metadata: Metadata = None,
        # server_side_encryption: ServerSideEncryption = None,
        # storage_class: StorageClass = None,
        # website_redirect_location: WebsiteRedirectLocation = None,
        # sse_customer_algorithm: SSECustomerAlgorithm = None,
        # sse_customer_key: SSECustomerKey = None,
        # sse_customer_key_md5: SSECustomerKeyMD5 = None,
        # ssekms_key_id: SSEKMSKeyId = None,
        # ssekms_encryption_context: SSEKMSEncryptionContext = None,
        # bucket_key_enabled: BucketKeyEnabled = None,
        # request_payer: RequestPayer = None,
        # tagging: TaggingHeader = None,
        # object_lock_mode: ObjectLockMode = None,
        # object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        # object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        # expected_bucket_owner: AccountId = None,
    ) -> PutObjectOutput:
        # TODO: validate order of validation

        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        if (
            storage_class := request.get("StorageClass")
        ) is not None and storage_class not in STORAGE_CLASSES:
            raise InvalidStorageClass(
                "The storage class you specified is not valid", StorageClassRequested=storage_class
            )

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, s3_bucket)

        key = request["Key"]
        headers = context.request.headers

        metadata = get_metadata_from_headers(headers)
        # set default ContentType
        if "ContentType" not in metadata:
            metadata["ContentType"] = "binary/octet-stream"

        # TODO: get all default from bucket, maybe extract logic

        # TODO: consolidate ACL into one, and validate it

        # until then, try that
        # get checksum value from request if present

        # TODO: validate the algo?
        checksum_algorithm = request.get("ChecksumAlgorithm")
        checksum_value = (
            request.get(f"Checksum{checksum_algorithm.upper()}") if checksum_algorithm else None
        )
        # validate encryption values

        # check if chunked request
        if headers.get("x-amz-content-sha256", "").startswith("STREAMING-"):
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
        else:
            decoded_content_length = None

        s3_object = S3Object(
            key=key,
            value=request.get("Body"),
            storage_class=storage_class,
            expires=request.get("Expires"),
            metadata=metadata,
            checksum_algorithm=checksum_algorithm,
            checksum_value=checksum_value,
            encryption=request.get("ServerSideEncryption"),
            kms_key_id=request.get("SSEKMSKeyId"),
            bucket_key_enabled=request.get("BucketKeyEnabled"),
            lock_mode=request.get("ObjectLockMode"),
            lock_legal_status=request.get("ObjectLockLegalHoldStatus"),
            lock_until=request.get("ObjectLockRetainUntilDate"),
            website_redirect_location=request.get("WebsiteRedirectLocation"),
            decoded_content_length=decoded_content_length,
            expiration=None,  # TODO, from lifecycle, or should it be updated with config?
            acl=None,
        )

        # TODO: set is_last for list objects
        if existing_s3_object := s3_bucket.objects.get(key):
            existing_s3_object.is_current = False

        # TODO: update versioning to include None, Enabled, Suspended
        # if None, version_id = None, Suspend = "null" Enabled = "random"
        if s3_bucket.versioning_status:
            # the bucket versioning is enabled, add the key to the list
            s3_bucket.objects[key] = s3_object
            s3_object.version_id = "something"
        else:
            # the bucket never had versioning enabled, set the key
            # or the bucket has versioning disabled, just override the last version
            s3_bucket.objects.set_last_version(key=key, value=s3_object)

        # TODO: tags: do we have tagging service or do we manually handle? see utils TaggingService
        #  add to store

        # TODO: fields
        # Expiration: Optional[Expiration] TODO
        # ETag: Optional[ETag] OK
        # ChecksumCRC32: Optional[ChecksumCRC32] OK
        # ChecksumCRC32C: Optional[ChecksumCRC32C] OK
        # ChecksumSHA1: Optional[ChecksumSHA1] OK
        # ChecksumSHA256: Optional[ChecksumSHA256] OK
        # ServerSideEncryption: Optional[ServerSideEncryption] OK
        # VersionId: Optional[ObjectVersionId] OK
        # SSECustomerAlgorithm: Optional[SSECustomerAlgorithm] ?
        # SSECustomerKeyMD5: Optional[SSECustomerKeyMD5] ?
        # SSEKMSKeyId: Optional[SSEKMSKeyId] OK
        # SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext] ?
        # BucketKeyEnabled: Optional[BucketKeyEnabled] OK
        # RequestCharged: Optional[RequestCharged]  # TODO
        response = PutObjectOutput(
            ETag=f'"{s3_object.etag}"',
        )
        if s3_object.version_id:  # TODO: better way?
            response["VersionId"] = s3_object.version_id

        if s3_object.checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = s3_object.checksum_value

        if s3_object.expiration:
            response["Expiration"] = s3_object.expiration  # TODO: properly parse the datetime

        if s3_object.encryption:
            response["ServerSideEncryption"] = s3_object.encryption
            if s3_object.encryption == ServerSideEncryption.aws_kms:
                if s3_object.kms_key_id is not None:
                    # TODO: see S3 AWS managed KMS key if not provided
                    response["SSEKMSKeyId"] = s3_object.kms_key_id
                if s3_object.bucket_key_enabled is not None:
                    response["BucketKeyEnabled"] = s3_object.bucket_key_enabled

        return response

    @handler("GetObject", expand=False)
    def get_object(
        self,
        context: RequestContext,
        request: GetObjectRequest,
        # bucket: BucketName,
        # key: ObjectKey,
        # if_match: IfMatch = None,
        # if_modified_since: IfModifiedSince = None,
        # if_none_match: IfNoneMatch = None,
        # if_unmodified_since: IfUnmodifiedSince = None,
        # range: Range = None,
        # response_cache_control: ResponseCacheControl = None,
        # response_content_disposition: ResponseContentDisposition = None,
        # response_content_encoding: ResponseContentEncoding = None,
        # response_content_language: ResponseContentLanguage = None,
        # response_content_type: ResponseContentType = None,
        # response_expires: ResponseExpires = None,
        # version_id: ObjectVersionId = None,
        # sse_customer_algorithm: SSECustomerAlgorithm = None,
        # sse_customer_key: SSECustomerKey = None,
        # sse_customer_key_md5: SSECustomerKeyMD5 = None,
        # request_payer: RequestPayer = None,
        # part_number: PartNumber = None,
        # expected_bucket_owner: AccountId = None,
        # checksum_mode: ChecksumMode = None,
    ) -> GetObjectOutput:
        # TODO: might add x-robot for system metadata??
        # Body: Optional[Union[Body, IO[Body], Iterable[Body]]]
        #     DeleteMarker: Optional[DeleteMarker] # TODO: this is on the NotFound exception actually?
        #     AcceptRanges: Optional[AcceptRanges]
        #     Expiration: Optional[Expiration]
        #     Restore: Optional[Restore]
        #     LastModified: Optional[LastModified]
        #     ContentLength: Optional[ContentLength]
        #     ETag: Optional[ETag]
        #     ChecksumCRC32: Optional[ChecksumCRC32]
        #     ChecksumCRC32C: Optional[ChecksumCRC32C]
        #     ChecksumSHA1: Optional[ChecksumSHA1]
        #     ChecksumSHA256: Optional[ChecksumSHA256]
        #     MissingMeta: Optional[MissingMeta]
        #     VersionId: Optional[ObjectVersionId]
        #     CacheControl: Optional[CacheControl]
        #     ContentDisposition: Optional[ContentDisposition]
        #     ContentEncoding: Optional[ContentEncoding]
        #     ContentLanguage: Optional[ContentLanguage]
        #     ContentRange: Optional[ContentRange]
        #     ContentType: Optional[ContentType]
        #     Expires: Optional[Expires]
        #     WebsiteRedirectLocation: Optional[WebsiteRedirectLocation]
        #     ServerSideEncryption: Optional[ServerSideEncryption]
        #     Metadata: Optional[Metadata]
        #     SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
        #     SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
        #     SSEKMSKeyId: Optional[SSEKMSKeyId]
        #     BucketKeyEnabled: Optional[BucketKeyEnabled]
        #     StorageClass: Optional[StorageClass]
        #     RequestCharged: Optional[RequestCharged]
        #     ReplicationStatus: Optional[ReplicationStatus]
        #     PartsCount: Optional[PartsCount]
        #     TagCount: Optional[TagCount]
        #     ObjectLockMode: Optional[ObjectLockMode]
        #     ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
        #     ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]
        #     StatusCode: Optional[GetObjectResponseStatusCode]

        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        object_key = request["Key"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        # TODO implement PartNumber once multipart is done

        s3_object = s3_bucket.get_object(
            key=object_key,
            version_id=request.get("VersionId"),
            http_method="GET",
        )

        # TODO implement special logic in serializer for S3, no specs for `x-amz-meta` headers, pass them as is
        # or maybe it's Metadata field? check and implement sysem/user metadata separation
        response = GetObjectOutput(
            AcceptRanges="bytes",
            **s3_object.get_metadata_headers(),
        )

        if checksum_algorithm := s3_object.checksum_algorithm:
            # this is a bug in AWS: it sets the content encoding header to an empty string (parity tested)
            response["ContentEncoding"] = ""
            if request.get("ChecksumMode") == "ENABLED":
                response[f"Checksum{checksum_algorithm.upper()}"] = checksum  # noqa

        if range_header := request.get("Range"):
            range_data = parse_range_header(range_header, s3_object.size)
            response["Body"] = s3_object.get_range_body_iterator(range_data)
            # TODO: should we set content-length? feels like it would allow chunk encoding but?? well parity says we should
            response["ContentRange"] = range_data.content_range
            response["ContentLength"] = range_data.content_length
        else:
            response["Body"] = s3_object.get_body_iterator()

        return response

    @handler("HeadObject", expand=False)
    def head_object(
        self,
        context: RequestContext,
        request: HeadObjectRequest,
        # bucket: BucketName,
        # key: ObjectKey,
        # if_match: IfMatch = None,
        # if_modified_since: IfModifiedSince = None,
        # if_none_match: IfNoneMatch = None,
        # if_unmodified_since: IfUnmodifiedSince = None,
        # range: Range = None,  # DONE
        # version_id: ObjectVersionId = None,
        # sse_customer_algorithm: SSECustomerAlgorithm = None,
        # sse_customer_key: SSECustomerKey = None,
        # sse_customer_key_md5: SSECustomerKeyMD5 = None,
        # request_payer: RequestPayer = None,
        # part_number: PartNumber = None,
        # expected_bucket_owner: AccountId = None,
        # checksum_mode: ChecksumMode = None,  # DONE
    ) -> HeadObjectOutput:
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        object_key = request["Key"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        # TODO implement PartNumber, don't know about part number + version id?
        s3_object = s3_bucket.get_object(
            key=object_key,
            version_id=request.get("VersionId"),
            http_method="HEAD",
        )

        # DeleteMarker: Optional[DeleteMarker]
        # AcceptRanges: Optional[AcceptRanges]
        # Expiration: Optional[Expiration]
        # Restore: Optional[Restore]
        # ArchiveStatus: Optional[ArchiveStatus]
        # LastModified: Optional[LastModified]
        # ContentLength: Optional[ContentLength]
        # ChecksumCRC32: Optional[ChecksumCRC32]
        # ChecksumCRC32C: Optional[ChecksumCRC32C]
        # ChecksumSHA1: Optional[ChecksumSHA1]
        # ChecksumSHA256: Optional[ChecksumSHA256]
        # ETag: Optional[ETag]
        # MissingMeta: Optional[MissingMeta]
        # VersionId: Optional[ObjectVersionId]
        # CacheControl: Optional[CacheControl]
        # ContentDisposition: Optional[ContentDisposition]
        # ContentEncoding: Optional[ContentEncoding]
        # ContentLanguage: Optional[ContentLanguage]
        # ContentType: Optional[ContentType]
        # Expires: Optional[Expires]
        # WebsiteRedirectLocation: Optional[WebsiteRedirectLocation]
        # ServerSideEncryption: Optional[ServerSideEncryption]
        # Metadata: Optional[Metadata]
        # SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
        # SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
        # SSEKMSKeyId: Optional[SSEKMSKeyId]
        # BucketKeyEnabled: Optional[BucketKeyEnabled]
        # StorageClass: Optional[StorageClass]
        # RequestCharged: Optional[RequestCharged]
        # ReplicationStatus: Optional[ReplicationStatus]
        # PartsCount: Optional[PartsCount]
        # ObjectLockMode: Optional[ObjectLockMode]
        # ObjectLockRetainUntilDate: Optional[ObjectLockRetainUntilDate]
        # ObjectLockLegalHoldStatus: Optional[ObjectLockLegalHoldStatus]

        response = HeadObjectOutput(
            AcceptRanges="bytes",
            **s3_object.get_metadata_headers(),
        )
        # TODO implements if_match if_modified_since if_none_match if_unmodified_since
        if checksum_algorithm := s3_object.checksum_algorithm:
            # this is a bug in AWS: it sets the content encoding header to an empty string (parity tested)
            response["ContentEncoding"] = ""
            if request.get("ChecksumMode") == "ENABLED":
                response[f"Checksum{checksum_algorithm.upper()}"] = checksum  # noqa

        if range_header := request.get("Range"):
            range_data = parse_range_header(range_header, s3_object.size)
            response["ContentLength"] = range_data.content_length

        if s3_object.parts is not None:
            response["PartsCount"] = len(s3_object.parts)

        if s3_object.version_id:
            response["VersionId"] = s3_object.version_id

        return response

    # @handler("DeleteObject", expand=False)
    def delete_object(
        self,
        context: RequestContext,
        # request: DeleteObjectRequest,
        bucket: BucketName,
        key: ObjectKey,
        mfa: MFA = None,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        bypass_governance_retention: BypassGovernanceRetention = None,
        expected_bucket_owner: AccountId = None,
    ) -> DeleteObjectOutput:
        # TODO: implement bypass_governance_retention, it is done in moto
        store = self.get_store(context.account_id, context.region)
        if not (s3_bucket := store.buckets.get(bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)

        # TODO: try if specifying VersionId to a never versioned bucket??
        if s3_bucket.versioning_status is None:  # never been versioned TODO: test
            s3_bucket.objects.pop(key, None)
            # TODO: RequestCharged
            return DeleteObjectOutput()

        if not version_id:
            delete_marker = S3DeleteMarker(key=key)
            # TODO: verify with Suspended bucket? does it override last version or still append?? big question
            # append the DeleteMaker to the objects stack
            # if the key does not exist already, AWS does not care and just append a DeleteMarker anyway
            s3_bucket.objects[key] = delete_marker
            return DeleteObjectOutput(VersionId=delete_marker.version_id, DeleteMarker=True)

        if (
            not (existed_versions := s3_bucket.objects.get_versions_for_key(key))
            or version_id not in existed_versions
        ):
            raise InvalidArgument(
                "Invalid version id specified",
                ArgumentName="versionId",
                ArgumentValue=version_id,
            )

        object_versions = s3_bucket.objects.getlist(key=key)

        found_object = None
        # TODO: probably use a lock, the list might change size as it's mutable
        for object_version in object_versions:
            if object_version.version_id == version_id:
                found_object = object_version

        if not found_object:
            return DeleteObjectOutput()

        response = DeleteObjectOutput(VersionId=found_object.version_id)
        # object versions is directly mutable, so we can directly remove the Object
        # to avoid concurrency issue, we will remove and not pop from the index
        # TODO: implementing locking, locked dict from persistence?
        with contextlib.suppress(ValueError):
            object_versions.remove(found_object)

        # if the list is now empty, pop the key entry
        if not object_versions:
            s3_bucket.objects.pop(key)

        if isinstance(found_object, S3DeleteMarker):
            response["DeleteMarker"] = True

        return response

    # @handler("DeleteObjects", expand=False)
    def delete_objects(
        self,
        context: RequestContext,
        # request: DeleteObjectsRequest,
        bucket: BucketName,
        delete: Delete,
        mfa: MFA = None,
        request_payer: RequestPayer = None,
        bypass_governance_retention: BypassGovernanceRetention = None,
        expected_bucket_owner: AccountId = None,
        checksum_algorithm: ChecksumAlgorithm = None,
    ) -> DeleteObjectsOutput:
        pass

    @handler("CopyObject", expand=False)
    def copy_object(
        self,
        context: RequestContext,
        request: CopyObjectRequest,
        # bucket: BucketName,
        # copy_source: CopySource,
        # key: ObjectKey,
        # acl: ObjectCannedACL = None,
        # cache_control: CacheControl = None,
        # checksum_algorithm: ChecksumAlgorithm = None,
        # content_disposition: ContentDisposition = None,
        # content_encoding: ContentEncoding = None,
        # content_language: ContentLanguage = None,
        # content_type: ContentType = None,
        # copy_source_if_match: CopySourceIfMatch = None,
        # copy_source_if_modified_since: CopySourceIfModifiedSince = None,
        # copy_source_if_none_match: CopySourceIfNoneMatch = None,
        # copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
        # expires: Expires = None,
        # grant_full_control: GrantFullControl = None,
        # grant_read: GrantRead = None,
        # grant_read_acp: GrantReadACP = None,
        # grant_write_acp: GrantWriteACP = None,
        # metadata: Metadata = None,
        # metadata_directive: MetadataDirective = None,
        # tagging_directive: TaggingDirective = None,
        # server_side_encryption: ServerSideEncryption = None,
        # storage_class: StorageClass = None,
        # website_redirect_location: WebsiteRedirectLocation = None,
        # sse_customer_algorithm: SSECustomerAlgorithm = None,
        # sse_customer_key: SSECustomerKey = None,
        # sse_customer_key_md5: SSECustomerKeyMD5 = None,
        # ssekms_key_id: SSEKMSKeyId = None,
        # ssekms_encryption_context: SSEKMSEncryptionContext = None,
        # bucket_key_enabled: BucketKeyEnabled = None,
        # copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm = None,
        # copy_source_sse_customer_key: CopySourceSSECustomerKey = None,
        # copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 = None,
        # request_payer: RequestPayer = None,
        # tagging: TaggingHeader = None,
        # object_lock_mode: ObjectLockMode = None,
        # object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        # object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        # expected_bucket_owner: AccountId = None,
        # expected_source_bucket_owner: AccountId = None,
    ) -> CopyObjectOutput:
        dest_bucket = request["Bucket"]
        dest_key = request["Bucket"]
        store = self.get_store(context.account_id, context.region)
        if not (dest_s3_bucket := store.buckets.get(dest_bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=dest_bucket)

        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request.get("CopySource")
        )

        if not (src_s3_bucket := store.buckets.get(src_bucket)):
            # TODO: validate this
            raise NoSuchBucket("The specified bucket does not exist", BucketName=src_bucket)

        # validate method not allowed?
        src_s3_object = src_s3_bucket.get_object(key=src_key, version_id=src_version_id)
        # TODO: validate StorageClass for ARCHIVES one
        if src_s3_object.storage_class in ARCHIVES_STORAGE_CLASSES:
            pass

        # TODO validate order of validation
        storage_class = request.get("StorageClass")
        server_side_encryption = request.get("ServerSideEncryption")
        metadata_directive = request.get("MetadataDirective")
        website_redirect_location = request.get("WebsiteRedirectLocation")
        if not any(
            (
                storage_class,
                server_side_encryption,
                metadata_directive == "REPLACE",
                website_redirect_location,
                dest_s3_bucket.encryption_rule,  # S3 will allow copy in place if the bucket has encryption configured
            )
        ):
            raise InvalidRequest(
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes."
            )

        metadata = get_metadata_from_headers(context.request.headers)
        # TODO: check metadata directive?? test it
        if metadata_directive == "UPDATE":
            metadata = {**src_s3_object.metadata, **metadata}

        # TODO test CopyObject that was created with multipart, can you query the Parts afterwards?
        s3_object = S3Object(
            key=dest_key,
            value=src_s3_object.value,
            storage_class=storage_class,
            expires=request.get("Expires"),
            metadata=metadata,
            checksum_algorithm=request.get("ChecksumAlgorithm") or src_s3_object.checksum_algorithm,
            checksum_value=None,
            encryption=request.get("ServerSideEncryption"),  # TODO inherit from bucket
            kms_key_id=request.get("SSEKMSKeyId"),
            bucket_key_enabled=request.get("BucketKeyEnabled"),
            lock_mode=request.get("ObjectLockMode"),
            lock_legal_status=request.get("ObjectLockLegalHoldStatus"),
            lock_until=request.get("ObjectLockRetainUntilDate"),
            website_redirect_location=website_redirect_location,
            expiration=None,  # TODO, from lifecycle, or should it be updated with config?
            acl=None,
        )
        # Object copied from Glacier object should not have expiry
        # TODO: verify this assumption from moto?

        # TODO: set is_last for list objects
        if existing_s3_object := dest_s3_bucket.objects.get(dest_key):
            existing_s3_object.is_current = False

        # TODO: update versioning to include None, Enabled, Suspended
        # if None, version_id = None, Suspend = "null" Enabled = "random"
        if dest_s3_bucket.versioning_status:
            # the bucket versioning is enabled, add the key to the list
            dest_s3_bucket.objects[dest_key] = s3_object
            s3_object.version_id = "something"
        else:
            # the bucket never had versioning enabled, set the key
            # or the bucket has versioning disabled, just override the last version
            dest_s3_bucket.objects.set_last_version(key=dest_key, value=s3_object)

        #     CopyObjectResult: Optional[CopyObjectResult]
        #     ETag: Optional[ETag]
        #     LastModified: Optional[LastModified]
        #     ChecksumCRC32: Optional[ChecksumCRC32]
        #     ChecksumCRC32C: Optional[ChecksumCRC32C]
        #     ChecksumSHA1: Optional[ChecksumSHA1]
        #     ChecksumSHA256: Optional[ChecksumSHA256]
        #     Expiration: Optional[Expiration]
        #     CopySourceVersionId: Optional[CopySourceVersionId]
        #     VersionId: Optional[ObjectVersionId]
        #     ServerSideEncryption: Optional[ServerSideEncryption]
        #     SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
        #     SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
        #     SSEKMSKeyId: Optional[SSEKMSKeyId]
        #     SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
        #     BucketKeyEnabled: Optional[BucketKeyEnabled]
        #     RequestCharged: Optional[RequestCharged]

        copy_object_result = CopyObjectResult(
            ETag=f'"{s3_object.etag}',
            LastModified=s3_object.last_modified,
        )
        if s3_object.checksum_algorithm:
            copy_object_result[
                f"Checksum{s3_object.checksum_algorithm.upper()}"
            ] = s3_object.checksum_value

        response = CopyObjectOutput(
            CopyObjectResult=copy_object_result,
        )

        if s3_object.version_id:  # TODO: better way?
            response["VersionId"] = s3_object.version_id

        if s3_object.expiration:
            response["Expiration"] = s3_object.expiration  # TODO: properly parse the datetime

        if s3_object.encryption:
            response["ServerSideEncryption"] = s3_object.encryption
            if s3_object.encryption == ServerSideEncryption.aws_kms:
                if s3_object.kms_key_id is not None:
                    # TODO: see S3 AWS managed KMS key if not provided
                    response["SSEKMSKeyId"] = s3_object.kms_key_id
                if s3_object.bucket_key_enabled is not None:
                    response["BucketKeyEnabled"] = s3_object.bucket_key_enabled

        if src_version_id:
            response["CopySourceVersionId"] = src_version_id

        return response

    # def list_objects(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     marker: Marker = None,
    #     max_keys: MaxKeys = None,
    #     prefix: Prefix = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListObjectsOutput:
    #     pass
    #
    # def list_objects_v2(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     max_keys: MaxKeys = None,
    #     prefix: Prefix = None,
    #     continuation_token: Token = None,
    #     fetch_owner: FetchOwner = None,
    #     start_after: StartAfter = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListObjectsV2Output:
    #     pass

    # def list_object_versions(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     key_marker: KeyMarker = None,
    #     max_keys: MaxKeys = None,
    #     prefix: Prefix = None,
    #     version_id_marker: VersionIdMarker = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListObjectVersionsOutput:
    #     pass

    @handler("GetObjectAttributes", expand=False)
    def get_object_attributes(
        self,
        context: RequestContext,
        request: GetObjectAttributesRequest,
    ) -> GetObjectAttributesOutput:
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        object_key = request["Key"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        # TODO implement PartNumber once multipart is done

        s3_object = s3_bucket.get_object(
            key=object_key,
            version_id=request.get("VersionId"),
            http_method="GET",
        )

        object_attrs = request.get("ObjectAttributes", [])
        response = GetObjectAttributesOutput()
        # TODO: see Checksum field
        if "ETag" in object_attrs:
            response["ETag"] = s3_object.etag
        if "StorageClass" in object_attrs:
            response["StorageClass"] = s3_object.storage_class
        if "ObjectSize" in object_attrs:
            response["ObjectSize"] = s3_object.size
        if "Checksum" in object_attrs and (checksum_algorithm := s3_object.checksum_algorithm):
            response["Checksum"] = {
                f"Checksum{checksum_algorithm.upper()}": s3_object.checksum_value
            }  # noqa

        response["LastModified"] = s3_object.last_modified

        # TODO enable more from this
        if s3_bucket.versioning_status:
            response["VersionId"] = s3_object.version_id

        if s3_object.parts is not None:
            response["ObjectParts"] = GetObjectAttributesParts(TotalPartsCount=len(s3_object.parts))

        return response

    # def restore_object(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     version_id: ObjectVersionId = None,
    #     restore_request: RestoreRequest = None,
    #     request_payer: RequestPayer = None,
    #     checksum_algorithm: ChecksumAlgorithm = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> RestoreObjectOutput:
    #     pass

    @handler("CreateMultipartUpload", expand=False)
    def create_multipart_upload(
        self,
        context: RequestContext,
        request: CreateMultipartUploadRequest,
        # bucket: BucketName,
        # key: ObjectKey,
        # acl: ObjectCannedACL = None,
        # cache_control: CacheControl = None,
        # content_disposition: ContentDisposition = None,
        # content_encoding: ContentEncoding = None,
        # content_language: ContentLanguage = None,
        # content_type: ContentType = None,
        # expires: Expires = None,
        # grant_full_control: GrantFullControl = None,
        # grant_read: GrantRead = None,
        # grant_read_acp: GrantReadACP = None,
        # grant_write_acp: GrantWriteACP = None,
        # metadata: Metadata = None,
        # server_side_encryption: ServerSideEncryption = None,
        # storage_class: StorageClass = None,
        # website_redirect_location: WebsiteRedirectLocation = None,
        # sse_customer_algorithm: SSECustomerAlgorithm = None,
        # sse_customer_key: SSECustomerKey = None,
        # sse_customer_key_md5: SSECustomerKeyMD5 = None,
        # ssekms_key_id: SSEKMSKeyId = None,
        # ssekms_encryption_context: SSEKMSEncryptionContext = None,
        # bucket_key_enabled: BucketKeyEnabled = None,
        # request_payer: RequestPayer = None,
        # tagging: TaggingHeader = None,
        # object_lock_mode: ObjectLockMode = None,
        # object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        # object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        # expected_bucket_owner: AccountId = None,
        # checksum_algorithm: ChecksumAlgorithm = None,
    ) -> CreateMultipartUploadOutput:
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        if (
            storage_class := request.get("StorageClass")
        ) is not None and storage_class not in STORAGE_CLASSES:
            raise InvalidStorageClass(
                "The storage class you specified is not valid", StorageClassRequested=storage_class
            )

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, s3_bucket)

        key = request["Key"]
        headers = context.request.headers

        metadata = get_metadata_from_headers(headers)
        # set default ContentType
        if "ContentType" not in metadata:
            metadata["ContentType"] = "binary/octet-stream"

        # TODO: get all default from bucket, maybe extract logic

        # TODO: consolidate ACL into one, and validate it

        # until then, try that
        # get checksum value from request if present

        # TODO: validate the algo?
        checksum_algorithm = request.get("ChecksumAlgorithm")

        # validate encryption values

        s3_multipart = S3Multipart(
            key=key,
            storage_class=storage_class,
            expires=request.get("Expires"),
            metadata=metadata,
            checksum_algorithm=checksum_algorithm,
            encryption=request.get("ServerSideEncryption"),
            kms_key_id=request.get("SSEKMSKeyId"),
            bucket_key_enabled=request.get("BucketKeyEnabled"),
            lock_mode=request.get("ObjectLockMode"),
            lock_legal_status=request.get("ObjectLockLegalHoldStatus"),
            lock_until=request.get("ObjectLockRetainUntilDate"),
            website_redirect_location=request.get("WebsiteRedirectLocation"),
            expiration=None,  # TODO, from lifecycle, or should it be updated with config?
            acl=None,
        )

        s3_bucket.multiparts[s3_multipart.upload_id] = s3_multipart

        # TODO: tags: do we have tagging service or do we manually handle? see utils TaggingService
        #  add to store

        # TODO: fields
        # AbortDate: Optional[AbortDate]  # TODO: lifecycle related
        # AbortRuleId: Optional[AbortRuleId] # TODO: lifecycle related
        # Bucket: Optional[BucketName]
        # Key: Optional[ObjectKey]
        # UploadId: Optional[MultipartUploadId]
        # ServerSideEncryption: Optional[ServerSideEncryption]
        # SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
        # SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
        # SSEKMSKeyId: Optional[SSEKMSKeyId]
        # SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
        # BucketKeyEnabled: Optional[BucketKeyEnabled]
        # RequestCharged: Optional[RequestCharged]
        # ChecksumAlgorithm: Optional[ChecksumAlgorithm]
        response = CreateMultipartUploadOutput(
            Bucket=bucket_name, Key=key, UploadId=s3_multipart.upload_id
        )

        if checksum_algorithm := s3_multipart.object.checksum_algorithm:
            response["ChecksumAlgorithm"] = checksum_algorithm

        if encryption := s3_multipart.object.encryption:
            response["ServerSideEncryption"] = encryption
            if encryption == ServerSideEncryption.aws_kms:
                if s3_multipart.object.kms_key_id is not None:
                    # TODO: see S3 AWS managed KMS key if not provided
                    response["SSEKMSKeyId"] = s3_multipart.object.kms_key_id
                if s3_multipart.object.bucket_key_enabled is not None:
                    response["BucketKeyEnabled"] = s3_multipart.object.bucket_key_enabled

        return response

    @handler("UploadPart", expand=False)
    def upload_part(
        self,
        context: RequestContext,
        request: UploadPartRequest,
        # bucket: BucketName,
        # key: ObjectKey,
        # part_number: PartNumber,
        # upload_id: MultipartUploadId,
        # body: IO[Body] = None,
        # content_length: ContentLength = None,
        # content_md5: ContentMD5 = None,
        # checksum_algorithm: ChecksumAlgorithm = None,
        # checksum_crc32: ChecksumCRC32 = None,
        # checksum_crc32_c: ChecksumCRC32C = None,
        # checksum_sha1: ChecksumSHA1 = None,
        # checksum_sha256: ChecksumSHA256 = None,
        # sse_customer_algorithm: SSECustomerAlgorithm = None,
        # sse_customer_key: SSECustomerKey = None,
        # sse_customer_key_md5: SSECustomerKeyMD5 = None,
        # request_payer: RequestPayer = None,
        # expected_bucket_owner: AccountId = None,
    ) -> UploadPartOutput:
        store = self.get_store(context.account_id, context.region)
        bucket_name = request["Bucket"]
        if not (s3_bucket := store.buckets.get(bucket_name)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket_name)

        upload_id = request.get("UploadId")
        if not (s3_multipart := s3_bucket.multiparts.get(upload_id)):
            raise NoSuchUpload(
                "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        # TODO: validate key?? is data model wrong??
        if s3_multipart.object.key != request.get("Key"):
            pass

        part_number = request.get("PartNumber")
        # TODO: validate PartNumber
        # if part_number > 10000:
        # raise InvalidMaxPartNumberArgument(part_number)

        headers = context.request.headers
        # check if chunked request
        if headers.get("x-amz-content-sha256", "").startswith("STREAMING-"):
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
        else:
            decoded_content_length = None

        checksum_algorithm = request.get("ChecksumAlgorithm")
        checksum_value = (
            request.get(f"Checksum{checksum_algorithm.upper()}") if checksum_algorithm else None
        )

        s3_part = S3Part(
            part_number=part_number,
            value=request.get("Body"),
            checksum_algorithm=checksum_algorithm,
            checksum_value=checksum_value,
            decoded_content_length=decoded_content_length,
        )

        s3_multipart.parts[part_number] = s3_part

        # ServerSideEncryption: Optional[ServerSideEncryption]
        # ETag: Optional[ETag]
        # ChecksumCRC32: Optional[ChecksumCRC32]
        # ChecksumCRC32C: Optional[ChecksumCRC32C]
        # ChecksumSHA1: Optional[ChecksumSHA1]
        # ChecksumSHA256: Optional[ChecksumSHA256]
        # SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
        # SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
        # SSEKMSKeyId: Optional[SSEKMSKeyId]
        # BucketKeyEnabled: Optional[BucketKeyEnabled]
        # RequestCharged: Optional[RequestCharged]
        response = UploadPartOutput(
            ETag=f'"{s3_part.etag}"',
        )

        # TODO: create helper
        if encryption := s3_multipart.object.encryption:
            response["ServerSideEncryption"] = encryption
            if encryption == ServerSideEncryption.aws_kms:
                if s3_multipart.object.kms_key_id is not None:
                    # TODO: see S3 AWS managed KMS key if not provided
                    response["SSEKMSKeyId"] = s3_multipart.object.kms_key_id
                if s3_multipart.object.bucket_key_enabled is not None:
                    response["BucketKeyEnabled"] = s3_multipart.object.bucket_key_enabled

        if s3_part.checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = s3_part.checksum_value

        return response

    @handler("UploadPartCopy", expand=False)
    def upload_part_copy(
        self,
        context: RequestContext,
        request: UploadPartCopyRequest,
        # bucket: BucketName,
        # copy_source: CopySource,
        # key: ObjectKey,
        # part_number: PartNumber,
        # upload_id: MultipartUploadId,
        # copy_source_if_match: CopySourceIfMatch = None,
        # copy_source_if_modified_since: CopySourceIfModifiedSince = None,
        # copy_source_if_none_match: CopySourceIfNoneMatch = None,
        # copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
        # copy_source_range: CopySourceRange = None,
        # sse_customer_algorithm: SSECustomerAlgorithm = None,
        # sse_customer_key: SSECustomerKey = None,
        # sse_customer_key_md5: SSECustomerKeyMD5 = None,
        # copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm = None,
        # copy_source_sse_customer_key: CopySourceSSECustomerKey = None,
        # copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 = None,
        # request_payer: RequestPayer = None,
        # expected_bucket_owner: AccountId = None,
        # expected_source_bucket_owner: AccountId = None,
    ) -> UploadPartCopyOutput:
        dest_bucket = request["Bucket"]
        dest_key = request["Bucket"]
        store = self.get_store(context.account_id, context.region)
        if not (dest_s3_bucket := store.buckets.get(dest_bucket)):
            raise NoSuchBucket("The specified bucket does not exist", BucketName=dest_bucket)

        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request.get("CopySource")
        )

        if not (src_s3_bucket := store.buckets.get(src_bucket)):
            # TODO: validate this
            raise NoSuchBucket("The specified bucket does not exist", BucketName=src_bucket)

        # validate method not allowed?
        src_s3_object = src_s3_bucket.get_object(key=src_key, version_id=src_version_id)
        # TODO: validate StorageClass for ARCHIVES one
        if src_s3_object.storage_class in ARCHIVES_STORAGE_CLASSES:
            pass

        upload_id = request.get("UploadId")
        if not (s3_multipart := dest_s3_bucket.multiparts.get(upload_id)):
            raise NoSuchUpload(
                "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )

        # TODO: validate key?? is data model wrong??
        if s3_multipart.object.key != dest_key:
            pass

        part_number = request.get("PartNumber")
        # TODO: validate PartNumber
        # if part_number > 10000:
        # raise InvalidMaxPartNumberArgument(part_number)

        source_range = request.get("CopySourceRange")
        # TODO implement copy source IF
        range_data = parse_range_header(source_range, src_s3_object.size)

        # TODO: PartialStream or use the Iterator??
        range_stream = PartialStream(
            base_stream=src_s3_object.value,
            range_data=range_data,
        )

        s3_part = S3Part(
            part_number=part_number,
            value=range_stream,
        )

        s3_multipart.parts[part_number] = s3_part

        #     CopySourceVersionId: Optional[CopySourceVersionId]
        #     CopyPartResult: Optional[CopyPartResult]
        # ETag: Optional[ETag]
        # LastModified: Optional[LastModified]
        # ChecksumCRC32: Optional[ChecksumCRC32]
        # ChecksumCRC32C: Optional[ChecksumCRC32C]
        # ChecksumSHA1: Optional[ChecksumSHA1]
        # ChecksumSHA256: Optional[ChecksumSHA256]
        #     ServerSideEncryption: Optional[ServerSideEncryption]
        #     SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
        #     SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
        #     SSEKMSKeyId: Optional[SSEKMSKeyId]
        #     BucketKeyEnabled: Optional[BucketKeyEnabled]
        #     RequestCharged: Optional[RequestCharged]

        result = CopyPartResult(
            ETag=s3_part.etag_header,
            LastModified=s3_part.last_modified,
        )

        if s3_part.checksum_algorithm:
            result[f"Checksum{s3_part.checksum_algorithm.upper()}"] = s3_part.checksum_value

        response = UploadPartCopyOutput(
            CopyPartResult=result,
        )

        if src_version_id:
            response["CopySourceVersionId"] = src_version_id

        # TODO: create helper
        if encryption := s3_multipart.object.encryption:
            response["ServerSideEncryption"] = encryption
            if encryption == ServerSideEncryption.aws_kms:
                if s3_multipart.object.kms_key_id is not None:
                    # TODO: see S3 AWS managed KMS key if not provided
                    response["SSEKMSKeyId"] = s3_multipart.object.kms_key_id
                if s3_multipart.object.bucket_key_enabled is not None:
                    response["BucketKeyEnabled"] = s3_multipart.object.bucket_key_enabled

        return response

    # def complete_multipart_upload(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     upload_id: MultipartUploadId,
    #     multipart_upload: CompletedMultipartUpload = None,
    #     checksum_crc32: ChecksumCRC32 = None,
    #     checksum_crc32_c: ChecksumCRC32C = None,
    #     checksum_sha1: ChecksumSHA1 = None,
    #     checksum_sha256: ChecksumSHA256 = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     sse_customer_key: SSECustomerKey = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    # ) -> CompleteMultipartUploadOutput:
    #     pass

    # def abort_multipart_upload(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     upload_id: MultipartUploadId,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> AbortMultipartUploadOutput:
    #     pass

    # def list_parts(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     upload_id: MultipartUploadId,
    #     max_parts: MaxParts = None,
    #     part_number_marker: PartNumberMarker = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     sse_customer_key: SSECustomerKey = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    # ) -> ListPartsOutput:
    #     pass

    # def list_multipart_uploads(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     key_marker: KeyMarker = None,
    #     max_uploads: MaxUploads = None,
    #     prefix: Prefix = None,
    #     upload_id_marker: UploadIdMarker = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListMultipartUploadsOutput:
    #     pass

    # def put_bucket_accelerate_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     accelerate_configuration: AccelerateConfiguration,
    #     expected_bucket_owner: AccountId = None,
    #     checksum_algorithm: ChecksumAlgorithm = None,
    # ) -> None:
    #     pass

    # def get_bucket_accelerate_configuration(
    #     self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    # ) -> GetBucketAccelerateConfigurationOutput:
    #     pass

    # def list_bucket_analytics_configurations(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     continuation_token: Token = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListBucketAnalyticsConfigurationsOutput:
    #     pass
    #
    # def delete_bucket_analytics_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     id: AnalyticsId,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     pass

    # def put_bucket_acl(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     acl: BucketCannedACL = None,
    #     access_control_policy: AccessControlPolicy = None,
    #     content_md5: ContentMD5 = None,
    #     checksum_algorithm: ChecksumAlgorithm = None,
    #     grant_full_control: GrantFullControl = None,
    #     grant_read: GrantRead = None,
    #     grant_read_acp: GrantReadACP = None,
    #     grant_write: GrantWrite = None,
    #     grant_write_acp: GrantWriteACP = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     pass
