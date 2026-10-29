import AuthPage from '@/AuthPage';
import SsoGate from '@/SsoGate';
export default function Register() {
  return (
    <div>
      <SsoGate>
        <AuthPage action="register" />
      </SsoGate>
    </div>
  );
}
