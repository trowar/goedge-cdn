Tea.context(function () {
	this.success = NotifyReloadSuccess("保存成功")

	/**
	 * 用户相关
	 */
	this.userSelectorVisible = false

	this.showUserSelector = function () {
		this.userSelectorVisible = !this.userSelectorVisible
	}

	this.userId = 0
	this.plans = []
	this.userPlanId = 0
	this.oldClusterId = this.server.clusterId

	if (this.userPlan != null) {
		this.userPlanId = this.userPlan.id
	}

	this.changeUserId = function (v) {
		// 单用户版本：不再提供套餐
		this.userId = v
		this.plans = []
	}
})