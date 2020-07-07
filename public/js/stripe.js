import axios from 'axios';
import { showAlert } from './alerts';

const stripe = Stripe(
  'pk_test_51GswiCDiQNJCFZtSUfkni64CrAN8bpU86wlhNc4D82GP4cjYuYA9KNMtluIVA2qPChBihs8Bp9KoEtl9rqTTyL6x00fEWB7o4n'
);

export const bookTour = async (tourId) => {
  try {
    //1. Get checkout session from API
    const session = await axios(
      `http://127.0.0.1:3000/api/v1/bookings/checkout-session/${tourId}`
    );
    console.log(session);

    //2. Create checkout form plus charge the credit card for us
    await stripe.redirectToCheckout({
      sessionId: session.data.session.id,
    });
  } catch (error) {
    console.log(err);
    showAlert('error', error);
  }
};
