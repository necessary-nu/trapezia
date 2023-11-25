use webauthn_rs::prelude::*;

use crate::session::SessionBackend;

pub struct PasskeyStrategy<S: PasskeySession> {
    webauthn: Webauthn,
    session_backend: S,
}

#[async_trait]
pub trait PasskeySession: SessionBackend {
    async fn remove_registration_state(&self, user_id: Uuid);

    // async fn start_register(
    //     &self,
    //     user_id: &[u8],
    //     username: &str,
    //     display_name: Option<&str>,
    //     session: (),
    // );

    // async fn finish_register(

    // );

    // async fn start_authentication();

    // async fn finish_authentication();
    // async fn store_auth_payload(&self, payload: &BankIdAuthPayload) -> Result<(), Self::Error>;
    // async fn auth_payload(&self, order_ref: &str) -> Result<BankIdAuthPayload, Self::Error>;
}

impl<S: PasskeySession> PasskeyStrategy<S> {
    pub async fn start_register(
        &self,
        user_id: Uuid,
        username: &str,
        display_name: Option<&str>,
        exclude_credential_ids: Vec<Base64UrlSafeData>,
        session: (),
    ) -> Result<CreationChallengeResponse, ()> {
        self.session_backend
            .remove_registration_state(user_id)
            .await;
        match self
            .webauthn
            .start_passkey_registration(
                user_id,
                username,
                display_name.unwrap_or(username),
                Some(exclude_credential_ids),
            )
            .await
        {
            Ok((ccr, reg_state)) => {
                self.session_backend
                    .set_registration_state(user_id, reg_state)
                    .await;

                Ok(ccr)
            }
            Err(e) => {
                // debug!("challenge_register -> {:?}", e);
                // return Err(WebauthnError::Unknown);
                Err(())
            }
        }
    }

    pub async fn finish_register(
        &self,
        user_id: Uuid,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, ()> {
        let reg_state = self
            .session_backend
            .consume_registration_state(user_id)
            .await;

        match self.webauthn.finish_passkey_registration(reg, &reg_state) {
            Ok(sk) => Ok(sk),
            Err(e) => {
                // debug!("challenge_register -> {:?}", e);
                // return Err(WebauthnError::Unknown);
                Err(())
            }
        }
    }

    pub async fn start_authentication(
        &self,
        user_id: Uuid,
        passkeys: &[Passkey],
    ) -> Result<RequestChallengeResponse, ()> {
        self.session_backend.remove_auth_state(user_id).await;

        match self.webauthn.start_passkey_authentication(passkeys) {
            Ok((rcr, auth_state)) => {
                self.session_backend
                    .set_auth_state(user_id, auth_state)
                    .await;

                Ok(rcr)
            }
            Err(e) => {
                // debug!("challenge_register -> {:?}", e);
                // return Err(WebauthnError::Unknown);
                Err(())
            }
        }
    }

    pub async fn finish_authentication(
        &self,
        user_id: Uuid,
        auth: &PublicKeyCredential,
    ) -> Result<(), ()> {
        let auth_state = self.session_backend.consume_auth_state().await;

        match self
            .webauthn
            .finish_passkey_authentication(auth, &auth_state)
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // debug!("challenge_register -> {:?}", e);
                // return Err(WebauthnError::Unknown);
                Err(())
            }
        }
    }
}
