<?php

namespace OAuth2;

use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;

class AuthServer
{
    /**
     * The delimeter between scopes specified in the scope query string parameter
     *
     * The OAuth 2 specification states it should be a space but that is stupid
     * and everyone excepted Google use a comma instead.
     *
     * @var string
     */
    protected $scopeDelimeter = ',';

    protected $expiresIn = 3600;

    protected $responseTypes = array();

    protected $storages = array();

    protected $grantTypes = array();

    protected $request = null;

    /**
     * Exception error codes
     * @var array
     */
    protected $exceptionCodes = array(
        0   =>  'invalid_request',
        1   =>  'unauthorized_client',
        2   =>  'access_denied',
        3   =>  'unsupported_response_type',
        4   =>  'invalid_scope',
        5   =>  'server_error',
        6   =>  'temporarily_unavailable',
        7   =>  'unsupported_grant_type',
        8   =>  'invalid_client',
        9   =>  'invalid_grant'
    );

    /**
     * Exception error messages
     * @var array
     */
    protected $exceptionMessages = array(
        'invalid_request'           =>  'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "%s" parameter.',
        'unauthorized_client'       =>  'The client is not authorized to request an access token using this method.',
        'access_denied'             =>  'The resource owner or authorization server denied the request.',
        'unsupported_response_type' =>  'The authorization server does not support obtaining an access token using this method.',
        'invalid_scope'             =>  'The requested scope is invalid, unknown, or malformed. Check the "%s" scope.',
        'server_error'              =>  'The authorization server encountered an unexpected condition which prevented it from fulfilling the request.',
        'temporarily_unavailable'   =>  'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
        'unsupported_grant_type'    =>  'The authorization grant type "%s" is not supported by the authorization server',
        'invalid_client'            =>  'Client authentication failed',
        'invalid_grant'             =>  'The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Check the "%s" parameter.',
        'invalid_credentials'       =>  'The user credentials were incorrect.',
        'invalid_refresh'           =>  'The refresh token is invalid.',
    );

    public function __construct(ClientInterface $client, SessionInterface $session, ScopeInterface $scope)
    {
        $this->storages = array(
            'client'    =>  $client,
            'session'   =>  $session,
            'scope' =>  $scope
        );
    }

    public function addGrantType(GrantTypeInterface $grantType, $identifier = null)
    {
        if (is_null($identifier)) {
            $identifier = $grantType->getIdentifier();
        }
        $this->grantTypes[$identifier] = $grantType;

        if (! is_null($grantType->getResponseType())) {
            $this->responseTypes[] = $grantType->getResponseType();
        }
    }

    public function getScopeDelimeter()
    {
        return $this->scopeDelimeter;
    }

    public function setScopeDelimeter($scope_delimeter)
    {
        $this->scopeDelimeter = $scope_delimeter;
    }

    public function getExpiresIn()
    {
        return $this->expiresIn;
    }

    public function setExpiresIn($expires_in)
    {
        $this->expiresIn = $expires_in;
    }

    /**
     * Sets the Request Object
     *
     * @param  RequestInterface The Request Object
     */
    public function setRequest(RequestInterface $request)
    {
        $this->request = $request;
    }

    /**
     * Gets the Request object.  It will create one from the globals if one is not set.
     *
     * @return  RequestInterface
     */
    public function getRequest()
    {
        if ($this->request === null) {
            $this->request = Request::buildFromGlobals();
        }

        return $this->request;
    }

    public function getStorage($obj)
    {
        return $this->storages[$obj];
    }

    /**
     * Check client authorise parameters
     *
     * @access public
     * @param  array $authParams Optional array of parsed $_GET keys
     * @return array             Authorise request parameters
     */
    public function checkClientAuthoriseParams($authParams = null)
    {

    }

    /**
     * Parse a new authorise request
     *
     * @param  string $type            The session owner's type
     * @param  string $typeId          The session owner's ID
     * @param  array  $authoriseParams The authorise request $_GET parameters
     * @return string                  An authorisation code
     */
    public function newAuthoriseRequest($type, $typeId, $authoriseParams)
    {

    }

    /**
     * Issue an access token
     *
     * @access public
     * @param  array $authParams Optional array of parsed $_POST keys
     * @return array             Authorise request parameters
     */
    public function issueAccessToken($authParams = null)
    {

    }


    protected function getCurrentGrantType()
    {
        $grantType = $this->getRequest()->post('grant_type');

        if (is_null($grantType)) {
            throw new Exception
        }
    }

}
