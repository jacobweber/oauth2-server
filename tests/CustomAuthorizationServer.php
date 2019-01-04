<?php

namespace LeagueTests;

use League\OAuth2\Server\AuthorizationServer;

class CustomAuthorizationServer extends AuthorizationServer
{
	protected function getResponseType()
	{
		$this->responseType = new CustomBearerTokenResponse();

		return parent::getResponseType();
	}
}
