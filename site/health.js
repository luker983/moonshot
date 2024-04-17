import {
  LitElement,
  html,
  css,
} from "https://cdn.jsdelivr.net/gh/lit/dist@3/core/lit-core.min.js";

export class Health extends LitElement {
  static properties = {
    healthy: { type: Boolean },
  };

  constructor() {
    super();
    this.healthy = true;
  }

  createRenderRoot() {
    return this;
  }

  render() {
    return html`
      <div class="container">
        <div class="row">
          <h6>Health Status</h6>
        </div>
        <div class="row">
          <i
            class="bi h1 align-middle mx-auto w-auto ${this.healthy
              ? "bi-check"
              : "blink bi-exclamation-triangle"}"
          ></i>
        </div>
      </div>
    `;
  }
}
customElements.define("health-metric", Health);
