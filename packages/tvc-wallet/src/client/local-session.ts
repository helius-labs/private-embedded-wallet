import {
  connectLocalUnattestedTvc,
  type LocalUnattestedConnectionConfig,
} from "./local-connection.js";
import { sessionFromConnector, type SprEmbeddedWalletSession } from "./session.js";

export function createLocalSprEmbeddedWalletSession(config: LocalUnattestedConnectionConfig): SprEmbeddedWalletSession {
  return sessionFromConnector((signal) => connectLocalUnattestedTvc(config, signal));
}
