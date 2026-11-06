// Copyright 2022 GoEdge CDN goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package users

import (
	"context"
	"errors"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
)

// FindUserPriceInfo 读取用户计费信息
func (this *UserService) FindUserPriceInfo(ctx context.Context, req *pb.FindUserPriceInfoRequest) (*pb.FindUserPriceInfoResponse, error) {
	return nil, this.NotImplementedYet()
}

// UpdateUserPriceType 修改用户计费方式
func (this *UserService) UpdateUserPriceType(ctx context.Context, req *pb.UpdateUserPriceTypeRequest) (*pb.RPCSuccess, error) {
	return nil, this.NotImplementedYet()
}

// UpdateUserPricePeriod 修改用户计费周期
func (this *UserService) UpdateUserPricePeriod(ctx context.Context, req *pb.UpdateUserPricePeriodRequest) (*pb.RPCSuccess, error) {
	return nil, this.NotImplementedYet()
}

// RegisterUser 注册用户
func (this *UserService) RegisterUser(ctx context.Context, req *pb.RegisterUserRequest) (*pb.RegisterUserResponse, error) {
	// 单用户版本：已禁用平台用户注册
	return nil, errors.New("当前系统为单用户版本，已禁用平台用户注册")
}

// FindUserFeatures 获取用户所有的功能列表
func (this *UserService) FindUserFeatures(ctx context.Context, req *pb.FindUserFeaturesRequest) (*pb.FindUserFeaturesResponse, error) {
	_, userId, err := this.ValidateAdminAndUser(ctx, false)
	if err != nil {
		return nil, err
	}
	if userId > 0 {
		req.UserId = userId
	}

	var tx = this.NullTx()

	features, err := models.SharedUserDAO.FindUserFeatures(tx, req.UserId)
	if err != nil {
		return nil, err
	}

	result := []*pb.UserFeature{}
	for _, feature := range features {
		result = append(result, feature.ToPB())
	}

	return &pb.FindUserFeaturesResponse{Features: result}, nil
}
