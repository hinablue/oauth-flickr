<?php 

/**
 * This Class depends on composer
 * "lusitanian/oauth": "1.0.*@dev"
 */
namespace OAuth\OAuth1\Service;

use OAuth\OAuth1\Signature\SignatureInterface;
use OAuth\OAuth1\Token\StdOAuth1Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Client\ClientInterface;

class Flickr extends AbstractService
{
    protected $extraHeaders = array();

    public function __construct(Credentials $credentials, ClientInterface $httpClient, TokenStorageInterface $storage, SignatureInterface $signature, UriInterface $baseApiUri = null)
    {
        parent::__construct($credentials, $httpClient, $storage, $signature, $baseApiUri);
        if( null === $baseApiUri ) {
            $this->baseApiUri = new Uri('http://www.flickr.com/services/api/');
        }
    }

    public function getRequestTokenEndpoint()
    {
        return new Uri('http://www.flickr.com/services/oauth/request_token');
    }

    public function getAuthorizationEndpoint()
    {
        return new Uri('http://www.flickr.com/services/oauth/authorize');
    }

    public function getAccessTokenEndpoint()
    {
        return new Uri('http://www.flickr.com/services/oauth/access_token');
    }

    public function parseRequestTokenResponse($responseBody) {
        parse_str($responseBody, $data);

        if( null === $data || !is_array($data) ) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif( isset($data['error'] ) ) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        return $this->parseAccessTokenResponse($responseBody);
    }

    public function parseAccessTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);

        if( null === $data || !is_array($data) ) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif( isset($data['error'] ) ) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth1Token();

        $token->setRequestToken( $data['oauth_token'] );
        $token->setRequestTokenSecret( $data['oauth_token_secret'] );
        $token->setAccessToken( $data['oauth_token'] );
        $token->setAccessTokenSecret( $data['oauth_token_secret'] );

        $token->setEndOfLife(StdOAuth1Token::EOL_NEVER_EXPIRES);
        unset( $data['oauth_token'], $data['oauth_token_secret'] );

        $token->setExtraParams( $data );

        return $token;
    }

    public function setExtraHeaders( array $extraHeaders ) {
        $this->extraHeaders = $extraHeaders;
    }

    protected function getExtraHeaders() {
        return $this->extraHeaders;
    }

    protected function getExtraOAuthHeaders()
    {
        return $this->getExtraHeaders();
    }

}