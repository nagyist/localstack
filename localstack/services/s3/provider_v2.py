from typing import Optional

from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import S3Api  # BucketName, CreateBucketConfiguration
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.s3.models_v2 import S3StoreV2, s3_stores_v2


class S3Provider(S3Api, ServiceLifecycleHook):
    @staticmethod
    def get_store(context: Optional[RequestContext] = None) -> S3StoreV2:
        # if not context:
        #     return s3_stores_v2[get_aws_account_id()][aws_stack.get_region()]
        # Use default account id for external access? would need an anonymous one?

        return s3_stores_v2[context.account_id][context.region]

    # def create_bucket(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     acl: BucketCannedACL = None,
    #     create_bucket_configuration: CreateBucketConfiguration = None,
    #     grant_full_control: GrantFullControl = None,
    #     grant_read: GrantRead = None,
    #     grant_read_acp: GrantReadACP = None,
    #     grant_write: GrantWrite = None,
    #     grant_write_acp: GrantWriteACP = None,
    #     object_lock_enabled_for_bucket: ObjectLockEnabledForBucket = None,
    #     object_ownership: ObjectOwnership = None,
    # ) -> CreateBucketOutput:
    #     raise NotImplementedError
    #
    # def delete_bucket(
    #     self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    # ) -> None:
    #     pass
    #
    # def list_buckets(
    #     self,
    #     context: RequestContext,
    # ) -> ListBucketsOutput:
    #     pass
    #
    # def head_bucket(
    #     self, context: RequestContext, bucket: BucketName, expected_bucket_owner: AccountId = None
    # ) -> HeadBucketOutput:
    #     pass
    #
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
