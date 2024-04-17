import {
  LitElement,
  html,
} from "https://cdn.jsdelivr.net/gh/lit/dist@3/core/lit-core.min.js";

export class Bar extends LitElement {
  static properties = {
    name: { type: String },
    value: { type: Number },
    min: { type: Number },
    max: { type: Number },
    icon: { type: String },
  };

  constructor() {
    super();
    this.name = "Unknown";
    this.value = 0;
    this.max = 100;
  }

  createRenderRoot() {
    return this;
  }

  render() {
    return html`
      <div class="container">
        <div class="row">
          <h6>${this.name}</h6>
        </div>
        <div class="row">
          <progress max="${this.max}" value="${this.value}">
            ${this.name}
          </progress>
        </div>
      </div>
    `;
  }
}
customElements.define("bar-metric", Bar);
