package acl

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/crossplane-contrib/provider-kafka/apis/v1alpha1"
	"github.com/crossplane-contrib/provider-kafka/internal/clients/kafka"

	"github.com/google/go-cmp/cmp"
	"github.com/twmb/franz-go/pkg/kadm"

	"k8s.io/apimachinery/pkg/util/json"
)


var baseACL = AccessControlList{
	ResourceName:              "acl1",
	ResourceType:              "Topic",
	ResourcePrincipal:         "User:Ken",
	ResourceHost:              "*",
	ResourceOperation:         "AlterConfigs",
	ResourcePermissionType:    "Allow",
	ResourcePatternTypeFilter: "Literal",
}

var baseJSONACL = `{	
		"ResourceName": "acl1",
		"ResourceType": "Topic",
		"ResourcePrincipal": "User:Ken",
		"ResourceHost": "*", 
		"ResourceOperation": "AlterConfigs",
		"ResourcePermissionType": "Allow",
		"ResourcePatternTypeFilter": "Literal"

		}`

var kafkaPassword = os.Getenv("KAFKA_PASSWORD")

var dataTesting = []byte(
	fmt.Sprintf(`{
			"brokers": ["kafka-dev-controller-0.kafka-dev-controller-headless.kafka-cluster.svc.cluster.local:9092","kafka-dev-controller-1.kafka-dev-controller-headless.kafka-cluster.svc.cluster.local:9092","kafka-dev-controller-2.kafka-dev-controller-headless.kafka-cluster.svc.cluster.local:9092"],
			"sasl": {
				"mechanism": "PLAIN",
				"username": "user1",
				"password": "%s"
			}
		}`, kafkaPassword),
)

var testACLs = []AccessControlList{
	{
		ResourceName:              "acl1",
		ResourceType:              "Topic",
		ResourcePrincipal:         "User:Ken",
		ResourceHost:              "*",
		ResourceOperation:         "AlterConfigs",
		ResourcePermissionType:    "Allow",
		ResourcePatternTypeFilter: "Literal",
	},
	{
		ResourceName:              "acl2",
		ResourceType:              "Group",
		ResourcePrincipal:         "User:Ken",
		ResourceHost:              "*",
		ResourceOperation:         "AlterConfigs",
		ResourcePermissionType:    "Allow",
		ResourcePatternTypeFilter: "Literal",
	},
	{
		ResourceName:              "acl3",
		ResourceType:              "TransactionalID",
		ResourcePrincipal:         "User:Ken",
		ResourceHost:              "*",
		ResourceOperation:         "AlterConfigs",
		ResourcePermissionType:    "Allow",
		ResourcePatternTypeFilter: "Literal",
	},
	{
		ResourceName:              "acl4",
		ResourceType:              "Cluster",
		ResourcePrincipal:         "User:Ken",
		ResourceHost:              "*",
		ResourceOperation:         "AlterConfigs",
		ResourcePermissionType:    "Allow",
		ResourcePatternTypeFilter: "Literal",
	},
	{
		ResourceName:              "acl5",
		ResourceType:              "Any",
		ResourcePrincipal:         "User:Ken",
		ResourceHost:              "*",
		ResourceOperation:         "AlterConfigs",
		ResourcePermissionType:    "Allow",
		ResourcePatternTypeFilter: "Literal",
	},
}

func TestCompareAcls(t *testing.T) {
	type args struct {
		extname  AccessControlList
		observed AccessControlList
	}

	aclTesting := baseACL

	cases := []struct {
		name string
		args args
		want bool
	}{

		{
			name: "PassCompare",
			args: args{
				extname: aclTesting,
				observed: AccessControlList{
					ResourceName:              "acl1",
					ResourceType:              "Topic",
					ResourcePrincipal:         "User:Ken",
					ResourceHost:              "*",
					ResourceOperation:         "AlterConfigs",
					ResourcePermissionType:    "Allow",
					ResourcePatternTypeFilter: "Literal",
				},
			},
			want: true,
		},
		{
			name: "FailAclName",
			args: args{
				extname: aclTesting,
				observed: AccessControlList{
					ResourceName:              "acl10",
					ResourceType:              "Topic",
					ResourcePrincipal:         "User:Ken",
					ResourceHost:              "*",
					ResourceOperation:         "AlterConfigs",
					ResourcePermissionType:    "Allow",
					ResourcePatternTypeFilter: "Literal",
				},
			},
			want: false,
		},
		{
			name: "FailResourceType",
			args: args{
				extname: aclTesting,
				observed: AccessControlList{
					ResourceName:              "acl1",
					ResourceType:              "Topical",
					ResourcePrincipal:         "User:Ken",
					ResourceHost:              "*",
					ResourceOperation:         "AlterConfigs",
					ResourcePermissionType:    "Allow",
					ResourcePatternTypeFilter: "Literal",
				},
			},
			want: false,
		},
		{
			name: "FailPrinciple",
			args: args{
				extname: aclTesting,
				observed: AccessControlList{
					ResourceName:              "acl1",
					ResourceType:              "Topic",
					ResourcePrincipal:         "User:NotKen",
					ResourceHost:              "*",
					ResourceOperation:         "AlterConfigs",
					ResourcePermissionType:    "Allow",
					ResourcePatternTypeFilter: "Literal",
				},
			},
			want: false,
		},
		{
			name: "FailSpecificHost",
			args: args{
				extname: aclTesting,
				observed: AccessControlList{
					ResourceName:              "acl1",
					ResourceType:              "Topic",
					ResourcePrincipal:         "User:Ken",
					ResourceHost:              "acme.com",
					ResourceOperation:         "AlterConfigs",
					ResourcePermissionType:    "Allow",
					ResourcePatternTypeFilter: "Literal",
				},
			},
			want: false,
		},
		{
			name: "FailOperationName",
			args: args{
				extname: aclTesting,
				observed: AccessControlList{
					ResourceName:              "acl1",
					ResourceType:              "Topic",
					ResourcePrincipal:         "User:Ken",
					ResourceHost:              "*",
					ResourceOperation:         "Read",
					ResourcePermissionType:    "Allow",
					ResourcePatternTypeFilter: "Literal",
				},
			},
			want: false,
		},
		{
			name: "FailPermissionType",
			args: args{
				extname: aclTesting,
				observed: AccessControlList{
					ResourceName:              "acl1",
					ResourceType:              "Topic",
					ResourcePrincipal:         "User:Ken",
					ResourceHost:              "*",
					ResourceOperation:         "AlterConfigs",
					ResourcePermissionType:    "Write",
					ResourcePatternTypeFilter: "Any",
				},
			},
			want: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareAcls(tt.args.extname, tt.args.observed)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("CompareAcls() = -want, +got:\n%s", diff)
			}
		})
	}
}

func TestConvertFromJSON(t *testing.T) {
	type args struct {
		extname string
	}

	baseACL := baseACL

	cases := []struct {
		name    string
		args    args
		want    *AccessControlList
		wantErr bool
	}{
		{
			name: "InvalidACL",
			args: args{
				extname: "acl1",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "ValidACL",
			args: args{
				extname: baseJSONACL,
			},
			want:    &baseACL,
			wantErr: false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertFromJSON(tt.args.extname)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("ConvertFromJSON() -want, +got:\n%s", diff)
			}
		})
	}
}

func TestConvertToJSON(t *testing.T) {
	type args struct {
		acl *AccessControlList
	}

	aclJSONMarshal, _ := json.Marshal(baseACL)
	aclJSONString := string(aclJSONMarshal)

	cases := map[string]struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		"PassJsonMarshal": {
			name: "SuccessfulMarshal",
			args: args{
				acl: &baseACL,
			},
			want:    aclJSONString,
			wantErr: false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertToJSON(tt.args.acl)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertToJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ConvertToJSON() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiff(t *testing.T) {
	type args struct {
		existing AccessControlList
		observed AccessControlList
	}

	cases := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "NoDifferences",
			args: args{
				existing: baseACL,
				observed: baseACL,
			},
			want: []string{},
		},
		{
			name: "WithDifferences",
			args: args{
				existing: baseACL,
				observed: AccessControlList{
					ResourceName:              "acl2",
					ResourceType:              "NewTopic",
					ResourcePrincipal:         "User:NotKen",
					ResourceHost:              "specifichost.com",
					ResourceOperation:         "Read",
					ResourcePermissionType:    "Deny",
					ResourcePatternTypeFilter: "Any",
				},
			},
			want: []string{
				"Resource Type has been updated, which is not allowed.",
				"Resource Principal has been updated, which is not allowed.",
				"Resource Host has been updated, which is not allowed.",
				"Resource Operation has been updated, which is not allowed.",
				"Resource Permission Type has been updated, which is not allowed.",
				"Resource Pattern Type Filter has been updated, which is not allowed.",
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := Diff(tt.args.existing, tt.args.observed); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Diff() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreate(t *testing.T) {
	newAc, _ := kafka.NewAdminClient(context.Background(), dataTesting, nil)

	type args struct {
		ctx               context.Context
		cl                *kadm.Client
		accessControlList *AccessControlList
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "CreateTopicACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[0],
			},
			wantErr: false,
		},
		{
			name: "CreateGroupACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[1],
			},
			wantErr: false,
		},
		{
			name: "CreateTransactionalIDACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[2],
			},
			wantErr: false,
		},
		{
			name: "CreateClusterACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[3],
			},
			wantErr: false,
		},
		{
			name: "CreateAnyResourceACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[4],
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Create(tt.args.ctx, tt.args.cl, tt.args.accessControlList); (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	newAc, _ := kafka.NewAdminClient(context.Background(), dataTesting, nil)

	type args struct {
		ctx               context.Context
		cl                *kadm.Client
		accessControlList *AccessControlList
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "DeleteTopicACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[0],
			},
			wantErr: false,
		},
		{
			name: "DeleteGroupACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[1],
			},
			wantErr: false,
		},
		{
			name: "DeleteTransactionalIDACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[2],
			},
			wantErr: false,
		},
		{
			name: "DeleteClusterACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[3],
			},
			wantErr: false,
		},
		{
			name: "DeleteAnyResourceACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[4],
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Delete(tt.args.ctx, tt.args.cl, tt.args.accessControlList); (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	type args struct {
		params *v1alpha1.AccessControlListParameters
	}
	tests := []struct {
		name string
		args args
		want *AccessControlList
	}{
		{
			name: "GenerateACL",
			args: args{
				params: (*v1alpha1.AccessControlListParameters)(&baseACL),
			},
			want: &baseACL,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Generate(tt.args.params); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Generate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUpToDate(t *testing.T) {
	type args struct {
		in       *v1alpha1.AccessControlListParameters
		observed *AccessControlList
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "IsUpToDateTrue",
			args: args{
				in: (*v1alpha1.AccessControlListParameters)(&baseACL),
				observed: &baseACL,
			},
			want: true,
		},
		{
			name: "TypeMismatchFalse",
			args: args{
				in: &v1alpha1.AccessControlListParameters{
					ResourceName: baseACL.ResourceName,
					ResourceType: "NewTopic",
					ResourcePrincipal:         baseACL.ResourcePrincipal,
					ResourceHost:              baseACL.ResourceHost,
					ResourceOperation:         baseACL.ResourceOperation,
					ResourcePermissionType:    baseACL.ResourcePermissionType,
					ResourcePatternTypeFilter: baseACL.ResourcePatternTypeFilter,
				},
				observed: &baseACL,
			},
			want: false,
		},
		{
			name: "PrincipalMismatchFalse",
			args: args{
				in: &v1alpha1.AccessControlListParameters{
					ResourceName: baseACL.ResourceName,
					ResourceType: baseACL.ResourceType,
					ResourcePrincipal:         "User:NotKen",
					ResourceHost:              baseACL.ResourceHost,
					ResourceOperation:         baseACL.ResourceOperation,
					ResourcePermissionType:    baseACL.ResourcePermissionType,
					ResourcePatternTypeFilter: baseACL.ResourcePatternTypeFilter,
				},
				observed: &baseACL,
			},
			want: false,
		},
		{
			name: "HostMismatchFalse",
			args: args{
				in: &v1alpha1.AccessControlListParameters{
					ResourceName: baseACL.ResourceName,
					ResourceType: baseACL.ResourceType,
					ResourcePrincipal:         baseACL.ResourcePrincipal,
					ResourceHost:              "specific.com",
					ResourceOperation:         baseACL.ResourceOperation,
					ResourcePermissionType:    baseACL.ResourcePermissionType,
					ResourcePatternTypeFilter: baseACL.ResourcePatternTypeFilter,
				},
				observed: &baseACL,
			},
			want: false,
		},
		{
			name: "OperationMismatchFalse",
			args: args{
				in: &v1alpha1.AccessControlListParameters{
					ResourceName: baseACL.ResourceName,
					ResourceType: baseACL.ResourceType,
					ResourcePrincipal:         baseACL.ResourcePrincipal,
					ResourceHost:              baseACL.ResourceHost,
					ResourceOperation:         "Read",
					ResourcePermissionType:    baseACL.ResourcePermissionType,
					ResourcePatternTypeFilter: baseACL.ResourcePatternTypeFilter,
				},
				observed: &baseACL,
			},
			want: false,
		},
		{
			name: "PermissionTypeMismatchFalse",
			args: args{
				in: &v1alpha1.AccessControlListParameters{
					ResourceName: baseACL.ResourceName,
					ResourceType: baseACL.ResourceType,
					ResourcePrincipal:         baseACL.ResourcePrincipal,
					ResourceHost:              baseACL.ResourceHost,
					ResourceOperation:         baseACL.ResourceOperation,
					ResourcePermissionType:    "Deny",
					ResourcePatternTypeFilter: baseACL.ResourcePatternTypeFilter,
				},
				observed: &baseACL,
			},
			want: false,
		},
		{
			name: "PatternTypeFilterMismatchFalse",
			args: args{
				in: &v1alpha1.AccessControlListParameters{
					ResourceName: baseACL.ResourceName,
					ResourceType: baseACL.ResourceType,
					ResourcePrincipal:         baseACL.ResourcePrincipal,
					ResourceHost:              baseACL.ResourceHost,
					ResourceOperation:         baseACL.ResourceOperation,
					ResourcePermissionType:    baseACL.ResourcePermissionType,
					ResourcePatternTypeFilter: "Any",
				},
				observed: &baseACL,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUpToDate(tt.args.in, tt.args.observed); got != tt.want {
				t.Errorf("IsUpToDate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestList(t *testing.T) {
	newAc, _ := kafka.NewAdminClient(context.Background(), dataTesting, nil)
	
	type args struct {
		ctx               context.Context
		cl                *kadm.Client
		accessControlList *AccessControlList
	}
	tests := []struct {
		name    string
		args    args
		want    *AccessControlList
		wantErr bool
	}{
		{
			name: "ListTopicACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[0],
			},
			wantErr: false,
		},
		{
			name: "ListGroupACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[1],
			},
			wantErr: false,
		},
		{
			name: "ListTransactionalIDACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[2],
			},
			wantErr: false,
		},
		{
			name: "ListClusterACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[3],
			},
			wantErr: false,
		},
		{
			name: "ListAnyResourceACL",
			args: args{
				ctx:               context.Background(),
				cl:                newAc,
				accessControlList: &testACLs[4],
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := List(tt.args.ctx, tt.args.cl, tt.args.accessControlList)
			if (err != nil) != tt.wantErr {
				t.Errorf("List() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("List() got = %v, want %v", got, tt.want)
			}
		})
	}
}
