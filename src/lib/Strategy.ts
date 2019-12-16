import { Issuer, generators, Client, ResponseType } from "openid-client";
import { Strategy } from "passport";
import { Request } from "express";

interface IOIDCConfig {
  scopes: string;
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  response_types: ResponseType[];
}

export class OIDCStrategy extends Strategy {
  name: string;

  constructor(private client: Client, private scopes: string) {
    super();
    this.name = "passport-openid-connect";
  }

  /**
   * static Create
   */
  public static Create = async (config: IOIDCConfig, issuerHost: string) => {
    const issuer = await Issuer.discover(issuerHost);
    const client = new issuer.Client({
      client_secret: config.client_secret,
      client_id: config.client_id,
      response_types: config.response_types,
      redirect_uris: config.redirect_uris
    });
    return new OIDCStrategy(client, config.scopes);
  };

  authenticate(req: Request, opts: any) {
    if (req.query["code"] || req.query["error"]) {
      return this.callback(req, opts);
    }
    if (!req.session) {
      return this.fail("No session");
    }

    const state = generators.state();
    req.session.auth_state = state;
    req.session.save(() => {
      const url = this.client.authorizationUrl({
        scope: this.scopes,
        state
      });
      this.redirect(url);
    });
  }

  async callback(req: Request, opts: any) {
    const params = this.client.callbackParams(req);
    if (!req.session || !req.session.auth_state) {
      return this.fail("Broken / no session");
    }
    try {
      const tokenSet = await this.client.callback(
        this.client.metadata.redirect_uris![0],
        params,
        { state: req.session.auth_state }
      );
      req.session.token = tokenSet.id_token;
      return this.success(tokenSet.claims());
    } catch (error) {
      console.error(error);
      return this.fail(error.message);
    }
  }
}
