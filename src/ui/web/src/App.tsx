import { StoreProvider, useStore } from "./store";
import { Shell } from "./components/Shell";
import { RoutesPage } from "./pages/Routes";
import { AddRoutePage } from "./pages/AddRoute";
import { PublishPage } from "./pages/Publish";
import { StatusPage } from "./pages/Status";
import { ListenersPage } from "./pages/Listeners";
import { ClustersPage } from "./pages/Clusters";
import { CertificatesPage } from "./pages/Certificates";
import { AuthPage } from "./pages/Auth";

function Page() {
  const { view, draft, loadError } = useStore();
  if (loadError) return <div className="notice err"><strong>The configuration could not be loaded.</strong> {loadError}</div>;
  if (!draft) return <p className="muted">Loading the configuration…</p>;
  switch (view) {
    case "status": return <StatusPage />;
    case "listeners": return <ListenersPage />;
    case "clusters": return <ClustersPage />;
    case "certificates": return <CertificatesPage />;
    case "auth": return <AuthPage />;
    case "publish": return <PublishPage />;
    case "add": return <AddRoutePage />;
    default: return <RoutesPage />;
  }
}

export function App() {
  return <StoreProvider><Shell><Page /></Shell></StoreProvider>;
}
