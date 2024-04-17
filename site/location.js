import {
  LitElement,
  html,
} from "https://cdn.jsdelivr.net/gh/lit/dist@3/core/lit-core.min.js";

export class Location extends LitElement {
  static properties = {
    lat: { type: Number },
    lon: { type: Number },
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
          <h6>Location</h6>
        </div>
        <div class="row">
          <div class="col">
            <h6>LAT: ${this.lat}</h3>
          </div>
          <div class="col">
            <h6>LON: ${this.lon}</h3>
            <div></div>
          </div>
        </div>
      </div>
    `;
  }
}
customElements.define("location-metric", Location);
