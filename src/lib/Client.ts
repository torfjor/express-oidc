import {
  Issuer,
  generators,
  Client,
  ResponseType,
  TokenSet
} from "openid-client";
import { Request } from "express";

interface IOIDCConfig {
  scopes: string;
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  response_types: ResponseType[];
}

type AuthenticateResponse = {
  state: string;
  url: string;
};

export class OIDCClient {
  constructor(private client: Client, private scopes: string) {}

  public static Create = async (config: IOIDCConfig, issuerHost: string) => {
    const issuer = await Issuer.discover(issuerHost);
    const client = new issuer.Client({
      client_secret: config.client_secret,
      client_id: config.client_id,
      response_types: config.response_types,
      redirect_uris: config.redirect_uris
    });
    return new OIDCClient(client, config.scopes);
  };

  authenticate(req: Request): AuthenticateResponse {
    const state = generators.state();
    const url = this.client.authorizationUrl({
      scope: this.scopes,
      state
    });

    return {
      state,
      url
    };
  }

  async login(
    code: string,
    state: string,
    savedState: string
  ): Promise<TokenSet> {
    const tokenSet = await this.client.callback(
      this.client.metadata.redirect_uris![0],
      { code, state },
      { state: savedState }
    );
    return tokenSet;
  }
}
