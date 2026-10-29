import AuthPage from '@/AuthPage';
import SsoGate from '@/SsoGate';

export default function Login() {
  return (
    <div>
      <SsoGate>
        <AuthPage action="login" />
      </SsoGate>
    </div>
  );
}
