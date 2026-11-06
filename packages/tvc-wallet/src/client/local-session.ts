import {
  connectLocalUnattestedTvc,
  type LocalUnattestedConnectionConfig,
} from "./local-connection.js";
import { sessionFromConnector, type TvcSession } from "./session.js";

export function createLocalTvcSession(config: LocalUnattestedConnectionConfig): TvcSession {
  return sessionFromConnector((signal) => connectLocalUnattestedTvc(config, signal));
}
