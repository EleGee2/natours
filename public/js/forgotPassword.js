import axios from 'axios';
import { showAlert } from './alerts';

export const forgotPassword = async (email) => {
  try {
    const res = await axios({
      method: 'POST',
      url: 'http://127.0.0.1:3000/api/v1/users/forgotPassword',
      data: {
        email,
      },
    });

    if (res.data.status === 'success') {
      showAlert(
        'success',
        "If we found an account associated with that username, we've sent password reset instructions to the primary email address on the account"
      );
    }
  } catch (err) {
    showAlert('error', err.response.data.message);
  }
};
