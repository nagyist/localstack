# from typing import Optional

from localstack import config

# from localstack.aws.api import CommonServiceException, RequestContext, ServiceException, handler
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.s3 import (  # BucketName, CreateBucketConfiguration,; InvalidBucketName,
    AccountId,
    Bucket,
    BucketAlreadyExists,
    BucketAlreadyOwnedByYou,
    BucketName,
    CreateBucketOutput,
    CreateBucketRequest,
    DeleteObjectOutput,
    DeleteObjectRequest,
    DeleteObjectsOutput,
    DeleteObjectsRequest,
    GetObjectAttributesOutput,
    GetObjectAttributesParts,
    GetObjectAttributesRequest,
    GetObjectOutput,
    GetObjectRequest,
    HeadBucketOutput,
    HeadObjectOutput,
    HeadObjectRequest,
    InvalidStorageClass,
    ListBucketsOutput,
    NoSuchBucket,
    PutObjectOutput,
    PutObjectRequest,
    S3Api,
    ServerSideEncryption,
    StorageClass,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.exceptions import (
    BucketNotEmpty,
    InvalidLocationConstraint,
    MalformedXML,
)
from localstack.services.s3.models_v2 import (
    S3Bucket,
    S3DeleteMarker,
    S3Object,
    S3StoreV2,
    s3_stores_v2,
)
from localstack.services.s3.utils import (
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

        # validate encryption values

        # check if chunked request
        if headers.get("x-amz-content-sha256", "").startswith("STREAMING-"):
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
        else:
            decoded_content_length = None

        s3_key = S3Object(
            key=key,
            value=request.get("Body"),
            storage_class=storage_class,
            expires=request.get("Expires"),
            metadata=metadata,
            checksum_algorithm=checksum_algorithm,
            checksum_value=request.get(f"Checksum{checksum_algorithm.upper()}")
            if checksum_algorithm
            else None,
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
            s3_bucket.objects[key] = s3_key
            s3_key.version_id = "something"
        else:
            # the bucket never had versioning enabled, set the key
            # or the bucket has versioning disabled, just override the last version
            s3_bucket.objects.set_last_version(key=key, value=s3_key)

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
            ETag=f'"{s3_key.etag}"',
        )
        if s3_key.version_id:  # TODO: better way?
            response["VersionId"] = s3_key.version_id

        if s3_key.checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = s3_key.checksum_value

        if s3_key.expiration:
            response["Expiration"] = s3_key.expiration  # TODO: properly parse the datetime

        if s3_key.encryption:
            response["ServerSideEncryption"] = s3_key.encryption
            if s3_key.encryption == ServerSideEncryption.aws_kms:
                if s3_key.kms_key_id is not None:
                    # TODO: see S3 AWS managed KMS key if not provided
                    response["SSEKMSKeyId"] = s3_key.kms_key_id
                if s3_key.bucket_key_enabled is not None:
                    response["BucketKeyEnabled"] = s3_key.bucket_key_enabled

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

        if version_id := request.get("VersionId"):
            if s3_bucket.versioning_status:
                s3_object = s3_bucket.objects.get_version(key=object_key, version_id=version_id)
            else:
                # TODO
                # can you provide a version id to a bucket with never activated versioning?
                s3_object = s3_bucket.objects.get(key=object_key)
                pass
        else:
            s3_object = s3_bucket.objects.get(key=object_key)

        if not s3_object:
            pass
        if isinstance(s3_object, S3DeleteMarker):
            pass

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
        if version_id := request.get("VersionId"):
            if s3_bucket.versioning_status:
                s3_object = s3_bucket.objects.get_version(key=object_key, version_id=version_id)
            else:
                # TODO
                # can you provide a version id to a bucket with never activated versioning?
                s3_object = s3_bucket.objects.get(key=object_key)
                pass
        else:
            s3_object = s3_bucket.objects.get(key=object_key)

        if not s3_object:
            pass
        if isinstance(s3_object, S3DeleteMarker):
            pass

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

        return response

    @handler("DeleteObject", expand=False)
    def delete_object(
        self,
        context: RequestContext,
        request: DeleteObjectRequest,
        # bucket: BucketName,
        # key: ObjectKey,
        # mfa: MFA = None,
        # version_id: ObjectVersionId = None,
        # request_payer: RequestPayer = None,
        # bypass_governance_retention: BypassGovernanceRetention = None,
        # expected_bucket_owner: AccountId = None,
    ) -> DeleteObjectOutput:
        pass

    @handler("DeleteObjects", expand=False)
    def delete_objects(
        self,
        context: RequestContext,
        request: DeleteObjectsRequest,
        # bucket: BucketName,
        # delete: Delete,
        # mfa: MFA = None,
        # request_payer: RequestPayer = None,
        # bypass_governance_retention: BypassGovernanceRetention = None,
        # expected_bucket_owner: AccountId = None,
        # checksum_algorithm: ChecksumAlgorithm = None,
    ) -> DeleteObjectsOutput:
        pass

    # def copy_object(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     copy_source: CopySource,
    #     key: ObjectKey,
    #     acl: ObjectCannedACL = None,
    #     cache_control: CacheControl = None,
    #     checksum_algorithm: ChecksumAlgorithm = None,
    #     content_disposition: ContentDisposition = None,
    #     content_encoding: ContentEncoding = None,
    #     content_language: ContentLanguage = None,
    #     content_type: ContentType = None,
    #     copy_source_if_match: CopySourceIfMatch = None,
    #     copy_source_if_modified_since: CopySourceIfModifiedSince = None,
    #     copy_source_if_none_match: CopySourceIfNoneMatch = None,
    #     copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
    #     expires: Expires = None,
    #     grant_full_control: GrantFullControl = None,
    #     grant_read: GrantRead = None,
    #     grant_read_acp: GrantReadACP = None,
    #     grant_write_acp: GrantWriteACP = None,
    #     metadata: Metadata = None,
    #     metadata_directive: MetadataDirective = None,
    #     tagging_directive: TaggingDirective = None,
    #     server_side_encryption: ServerSideEncryption = None,
    #     storage_class: StorageClass = None,
    #     website_redirect_location: WebsiteRedirectLocation = None,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     sse_customer_key: SSECustomerKey = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    #     ssekms_key_id: SSEKMSKeyId = None,
    #     ssekms_encryption_context: SSEKMSEncryptionContext = None,
    #     bucket_key_enabled: BucketKeyEnabled = None,
    #     copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm = None,
    #     copy_source_sse_customer_key: CopySourceSSECustomerKey = None,
    #     copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 = None,
    #     request_payer: RequestPayer = None,
    #     tagging: TaggingHeader = None,
    #     object_lock_mode: ObjectLockMode = None,
    #     object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
    #     object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
    #     expected_bucket_owner: AccountId = None,
    #     expected_source_bucket_owner: AccountId = None,
    # ) -> CopyObjectOutput:
    #     pass

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

        if version_id := request.get("VersionId"):
            if s3_bucket.versioning_status:
                s3_object = s3_bucket.objects.get_version(key=object_key, version_id=version_id)
            else:
                # TODO
                # can you provide a version id to a bucket with never activated versioning?
                s3_object = s3_bucket.objects.get(key=object_key)
                pass
        else:
            s3_object = s3_bucket.objects.get(key=object_key)

        if not s3_object:
            pass
        if isinstance(s3_object, S3DeleteMarker):
            pass

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

    #
    #
    # def get_bucket_location(
    #     self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    # ) -> GetBucketLocationOutput:
    #     pass
    #
    #
    # def put_bucket_accelerate_configuration(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     accelerate_configuration: AccelerateConfiguration,
    #     expected_bucket_owner: AccountId = None,
    #     checksum_algorithm: ChecksumAlgorithm = None,
    # ) -> None:
    #     pass
    #
    # def get_bucket_accelerate_configuration(
    #     self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    # ) -> GetBucketAccelerateConfigurationOutput:
    #     pass
    #
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
    #
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
