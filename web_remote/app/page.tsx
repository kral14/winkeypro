import { requireChatGPTUser } from "./chatgpt-auth";
import Dashboard from "./dashboard";
export const dynamic = "force-dynamic";
export default async function Home() { const user = await requireChatGPTUser("/"); return <Dashboard userName={user.displayName} />; }
