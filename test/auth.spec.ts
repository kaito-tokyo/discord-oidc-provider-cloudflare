import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi } from 'vitest';

describe('/auth', () => {
  const OIDC_CLIENT_ID = 'oidc-client-id';
  const OIDC_REDIRECT_URI = 'http://localhost/callback';
  const DISCORD_CLIENT_ID = 'discord-client-id';

  it('should redirect to Discord with valid parameters', async () => {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: OIDC_CLIENT_ID,
      redirect_uri: OIDC_REDIRECT_URI,
      scope: 'openid profile',
      state: 'test_state',
      nonce: 'test_nonce',
      code_challenge: 'test_code_challenge',
      code_challenge_method: 'S256',
    });
    const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
    expect(response.status).toBe(302);
    const redirectUrl = new URL(response.headers.get('location')!);
    expect(redirectUrl.hostname).toBe('discord.com');
    expect(redirectUrl.pathname).toBe('/api/oauth2/authorize');
    expect(redirectUrl.searchParams.get('client_id')).toBe(DISCORD_CLIENT_ID);
    expect(redirectUrl.searchParams.get('redirect_uri')).toBe('http://localhost/callback');
    expect(redirectUrl.searchParams.get('response_type')).toBe('code');
    expect(redirectUrl.searchParams.get('scope')).toBe('identify'); // Default scope
    expect(redirectUrl.searchParams.get('state')).toBeDefined();
  });

  it('should include email scope if requested', async () => {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: OIDC_CLIENT_ID,
      redirect_uri: OIDC_REDIRECT_URI,
      scope: 'openid email',
      state: 'test_state',
      nonce: 'test_nonce',
      code_challenge: 'test_code_challenge',
      code_challenge_method: 'S256',
    });
    const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
    expect(response.status).toBe(302);
    const redirectUrl = new URL(response.headers.get('location')!);
    expect(redirectUrl.searchParams.get('scope')).toBe('identify email');
  });

  it('should return 400 for invalid response_type', async () => {
    const params = new URLSearchParams({
      response_type: 'token', // Invalid
      client_id: OIDC_CLIENT_ID,
      redirect_uri: OIDC_REDIRECT_URI,
      scope: 'openid',
      state: 'test_state',
      nonce: 'test_nonce',
      code_challenge: 'test_code_challenge',
    });
    const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
    expect(response.status).toBe(302);
    const redirectUrl = new URL(response.headers.get('location')!);
    expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
    expect(redirectUrl.searchParams.get('error_description')).toBe('invalid response_type');
  });

  it('should return 400 for invalid client_id', async () => {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: 'wrong_client_id', // Invalid
      redirect_uri: OIDC_REDIRECT_URI,
      scope: 'openid',
      state: 'test_state',
      nonce: 'test_nonce',
      code_challenge: 'test_code_challenge',
    });
    const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
    expect(response.status).toBe(302);
    const redirectUrl = new URL(response.headers.get('location')!);
    expect(redirectUrl.searchParams.get('error')).toBe('unauthorized_client');
    expect(redirectUrl.searchParams.get('error_description')).toBe('invalid client_id');
  });

  it('should return 400 for invalid redirect_uri', async () => {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: OIDC_CLIENT_ID,
      redirect_uri: 'http://localhost/wrong_callback', // Invalid
      scope: 'openid',
      state: 'test_state',
      nonce: 'test_nonce',
      code_challenge: 'test_code_challenge',
    });
    const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
    expect(response.status).toBe(400);
    expect(await response.text()).toEqual('invalid redirect_uri');
  });

  it('should return 400 if openid scope is missing', async () => {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: OIDC_CLIENT_ID,
      redirect_uri: OIDC_REDIRECT_URI,
      scope: 'profile', // Missing openid
      state: 'test_state',
      nonce: 'test_nonce',
      code_challenge: 'test_code_challenge',
    });
    const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
    expect(response.status).toBe(302);
    const redirectUrl = new URL(response.headers.get('location')!);
    expect(redirectUrl.searchParams.get('error')).toBe('invalid_scope');
    expect(redirectUrl.searchParams.get('error_description')).toBe('invalid scope');
  });

  it('should return 400 if state is missing', async () => {
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: OIDC_CLIENT_ID,
        redirect_uri: OIDC_REDIRECT_URI,
        scope: 'openid',
        nonce: 'test_nonce',
        code_challenge: 'test_code_challenge',
      });
      const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const redirectUrl = new URL(response.headers.get('location')!);
      expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
      expect(redirectUrl.searchParams.get('error_description')).toBe('state is required');
    });

    it('should redirect successfully even if nonce is missing', async () => {
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: OIDC_CLIENT_ID,
        redirect_uri: OIDC_REDIRECT_URI,
        scope: 'openid',
        state: 'test_state',
        code_challenge: 'test_code_challenge',
      });
      const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const redirectUrl = new URL(response.headers.get('location')!);
      expect(redirectUrl.searchParams.get('code')).toBeDefined();
      expect(redirectUrl.searchParams.get('state')).toBeDefined();
    });

    it('should return 400 if code_challenge is missing', async () => {
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: OIDC_CLIENT_ID,
        redirect_uri: OIDC_REDIRECT_URI,
        scope: 'openid',
        state: 'test_state',
        nonce: 'test_nonce',
      });
      const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const redirectUrl = new URL(response.headers.get('location')!);
      expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
      expect(redirectUrl.searchParams.get('error_description')).toBe('code_challenge is required');
    });

    it('should return 400 if code_challenge_method is not supported', async () => {
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: OIDC_CLIENT_ID,
        redirect_uri: OIDC_REDIRECT_URI,
        scope: 'openid',
        state: 'test_state',
        nonce: 'test_nonce',
        code_challenge: 'test_code_challenge',
        code_challenge_method: 'plain', // Not supported
      });
      const response = await SELF.fetch(`http://localhost/auth?${params.toString()}`, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const redirectUrl = new URL(response.headers.get('location')!);
      expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
      expect(redirectUrl.searchParams.get('error_description')).toBe('code_challenge_method is not supported');
    });
});
