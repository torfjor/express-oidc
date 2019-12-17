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

  authenticate(req: Request): string {
    if (!req.session) {
      throw new Error("no session");
    }

    const state = generators.state();
    req.session.auth_state = state;
    return this.client.authorizationUrl({
      scope: this.scopes,
      state
    });
  }

  async login(req: Request): Promise<TokenSet> {
    if (!req.session || !req.session.auth_state) {
      throw new Error("broken / no session");
    }

    if (!req.query["code"] || !req.query["state"]) {
      throw new Error("missing code and/or state parameter");
    }

    const params = this.client.callbackParams(req);
    const tokenSet = await this.client.callback(
      this.client.metadata.redirect_uris![0],
      params,
      { state: req.session.auth_state }
    );
    return tokenSet;
  }
}
