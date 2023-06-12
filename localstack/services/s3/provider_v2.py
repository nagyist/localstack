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
from localstack.services.s3.models_v2 import S3Bucket, S3Object, S3StoreV2, s3_stores_v2
from localstack.services.s3.utils import (
    get_class_attrs_from_spec_class,
    get_full_default_bucket_location,
    get_metadata_from_headers,
    get_owner_for_account_id,
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

        metadata = get_metadata_from_headers(context.request.headers)

        # TODO: get all default from bucket, maybe extract logic

        # TODO: consolidate ACL into one, and validate it

        # until then, try that
        # get checksum value from request if present

        # TODO: validate the algo?
        checksum_algorithm = request.get("ChecksumAlgorithm")

        # validate encryption values

        s3_key = S3Object(
            key=key,
            value=request.get("Body"),
            storage_class=storage_class,
            metadata=metadata,
            checksum_algorithm=checksum_algorithm,
            checksum_value=request.get(f"Checksum{checksum_algorithm.upper()}"),
            encryption=request.get("ServerSideEncryption"),
            kms_key_id=request.get("SSEKMSKeyId"),
            bucket_key_enabled=request.get("BucketKeyEnabled"),
            lock_mode=request.get("ObjectLockMode"),
            lock_legal_status=request.get("ObjectLockLegalHoldStatus"),
            lock_until=request.get("ObjectLockRetainUntilDate"),
            acl=None,
        )

        existing_s3_object = s3_bucket.objects.get(key)
        # TODO: set is_last for list objects
        if existing_s3_object:
            existing_s3_object.is_current = False

        if s3_bucket.versioning_status:
            # the bucket versioning is enabled, add the key to the list
            s3_bucket.objects[key] = s3_key
        else:
            # the bucket never had versioning enabled, set the key
            # or the bucket has versioning disabled, just override the last version
            s3_bucket.objects.set_last_version(key=key, value=s3_key)

        # TODO: fields
        # Expiration: Optional[Expiration]
        # ETag: Optional[ETag]
        # ChecksumCRC32: Optional[ChecksumCRC32]
        # ChecksumCRC32C: Optional[ChecksumCRC32C]
        # ChecksumSHA1: Optional[ChecksumSHA1]
        # ChecksumSHA256: Optional[ChecksumSHA256]
        # ServerSideEncryption: Optional[ServerSideEncryption]
        # VersionId: Optional[ObjectVersionId]
        # SSECustomerAlgorithm: Optional[SSECustomerAlgorithm]
        # SSECustomerKeyMD5: Optional[SSECustomerKeyMD5]
        # SSEKMSKeyId: Optional[SSEKMSKeyId]
        # SSEKMSEncryptionContext: Optional[SSEKMSEncryptionContext]
        # BucketKeyEnabled: Optional[BucketKeyEnabled]
        # RequestCharged: Optional[RequestCharged]
        response = PutObjectOutput(
            ETag=s3_key.etag,
        )
        if s3_key.checksum_algorithm:
            response[f"Checksum{checksum_algorithm.upper()}"] = s3_key.checksum_value
        if s3_key.expiry:
            response["Expiration"] = s3_key.expiry  # TODO: properly parse the datetime
        if s3_key.encryption:
            response["ServerSideEncryption"] = s3_key.encryption
            if s3_key.encryption == ServerSideEncryption.aws_kms:
                # Add key and bucket key enabled
                pass

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
        pass

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
        # range: Range = None,
        # version_id: ObjectVersionId = None,
        # sse_customer_algorithm: SSECustomerAlgorithm = None,
        # sse_customer_key: SSECustomerKey = None,
        # sse_customer_key_md5: SSECustomerKeyMD5 = None,
        # request_payer: RequestPayer = None,
        # part_number: PartNumber = None,
        # expected_bucket_owner: AccountId = None,
        # checksum_mode: ChecksumMode = None,
    ) -> HeadObjectOutput:
        pass

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
